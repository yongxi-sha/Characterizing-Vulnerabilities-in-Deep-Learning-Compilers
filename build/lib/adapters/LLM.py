import os
import re
import sys
import base64
try:
    import openai
except Exception:
    openai = None
import requests
import time

class LLMAgent:
    def __init__(self, model="gpt-4", temperature=0.7):
        self.model = model
        self.temperature = temperature

    def get_sg_prompt(self, project, command, description):
        return (
            f"Given the project profile:\n{project}\n"
            f"The program runs as: `{command} <input>`.\n"
            f"Description: {description}\n\n"
            "Based on this, generate exactly 10 valid and diverse **input content** that match the expected input format.\n"
            "Each input should be minimal, simple, and formatted as a string suitable for a test file.\n"
            "\n"
            "Please output the inputs as a numbered list in the following format:\n"
            "1. \"<input content 1>\"\n"
            "...\n"
            "10. \"<input content 10>\"\n"
            "Use plain text only, no markdown or explanations."
        )

    def extract_blocks(self, seed_text):
        regex_array = [
            r'\d+\.\s+"<input content=\'(.*?)\'>"',
            r'\d+\.\s+`"?([^`"]+?)"?`',
            r'\d+\.\s+"(.*?)"',
            r'\d+\.\s+```(?:\w+)?\s*"(.*?)"\s*```'
        ]
        for regex in regex_array:
            blocks = re.findall(regex, seed_text, re.DOTALL)
            if blocks:
                return [block.strip().strip('"\'') for block in blocks if block.strip()]
        return []

    def save_seeds(self, is_base64, seed_text, seed_path, prefix="seed"):
        os.makedirs(seed_path, exist_ok=True)
        inputs = self.extract_blocks(seed_text)
        print(inputs)

        count = 0
        for i, input_text in enumerate(inputs):
            file_path = os.path.join(seed_path, f"{prefix}{i+1}")
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    if is_base64:
                        try:
                            decoded = base64.b64decode(input_text.encode('utf-8'))
                            input_text = decoded.decode('utf-8')
                        except Exception:
                            pass
                    f.write(input_text)
                count += 1
            except Exception as e:
                print(f"[!] Failed to write seed {i+1}: {e}")

        print(f"[+] Saved {count} seed file(s) to {seed_path}")
        return count
    
    def normalize_opt_values(self, content):
        lines = content.strip().splitlines()
        results = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            match = re.match(r"^\d+\.\s*(.+)", line)  # match "1. value"
            if match:
                results.append(match.group(1).strip())
            else:
                results.append(line)  # plain line, like "value"
        return results
    
    def get_opt_values_prompt(self, cmd, opt, arg, desc, num=5):
        return (
            f"The command-line is: {cmd} {opt} <{arg}>\n"
            f"Description: {desc}\n\n"
            f"Generate {num} meaningful and diverse values for <{arg}> as plain values (just the argument part, without the option prefix).\n"
            "These values should be realistic, syntactically valid, and semantically appropriate.\n"
            "Output only one value per line. No markdown, no explanation, no quotes, each less than 256 characters/bytes"
        )

    def generate_seeds(self, project, driver, seed_path):
        raise NotImplementedError("Must be implemented in subclass")

    def get_opt_values(self, cmd, opt, arg, desc, num=3) -> list:
        raise NotImplementedError("Must be implemented in subclass")


class OpenAIAgent(LLMAgent):
    def __init__(self, model="gpt-4", temperature=0.7):
        super().__init__(model, temperature)
        if openai is None:
            raise RuntimeError("openai package is not installed. Please install 'openai' to use OpenAIAgent.")
        self.client = openai.OpenAI()

    def generate_seeds(self, project, driver, seed_path):
        cmd = " ".join([driver.driver] + driver.args)
        prompt = self.get_sg_prompt(project.to_string(), cmd, driver.description)
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature
            )
            content = response.choices[0].message.content
            print(content)
            return self.save_seeds(project.is_base64_encoding(), content, seed_path)
        except Exception as e:
            print(f"[!] LLM request failed: {e}")
            return 0

    def get_opt_values(self, cmd, opt, arg, desc, num=3) -> list:
        prompt = self.get_opt_values_prompt(cmd, opt, arg, desc, num)
        try:
            print(prompt)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature
            )
            content = response.choices[0].message.content
            return self.normalize_opt_values(content)
        except Exception as e:
            print(f"[!] LLM opt value generation failed for {cmd} {opt}: {e}")
            return []


class DPAgent(LLMAgent):
    def __init__(self, model="mistralai/Mistral-7B-Instruct-v0.1", temperature=0.7, api_key=None):
        super().__init__(model, temperature)
        self.api_key = "671853f579c1533319ac362ee463d8b3c159a0b1d0ab318532dbb56fd5d9f0df"
        self.endpoint = "https://api.together.xyz/v1/chat/completions"
        self._min_interval_sec = 1.1  # obey 1 QPS
        self._last_request_ts = 0.0

    def _post_prompt(self, prompt, max_retries: int = 5, initial_delay: float = 1.0):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature
        }
        # Basic client-side rate limiting (1 QPS)
        now = time.time()
        sleep_needed = self._min_interval_sec - (now - self._last_request_ts)
        if sleep_needed > 0:
            time.sleep(sleep_needed)

        delay = initial_delay
        for attempt in range(1, max_retries + 1):
            try:
                response = requests.post(self.endpoint, headers=headers, json=payload, timeout=60)
                self._last_request_ts = time.time()

                if response.status_code == 200:
                    return response.json()["choices"][0]["message"]["content"]

                # Handle rate limit explicitly
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    if retry_after is not None:
                        try:
                            delay = max(float(retry_after), delay)
                        except Exception:
                            pass
                    # exponential backoff with jitter
                    if attempt < max_retries:
                        time.sleep(delay + (0.1 * attempt))
                        delay *= 2
                        continue

                # Other non-200s: retry a few times, then surface minimal error
                if attempt < max_retries:
                    time.sleep(delay)
                    delay *= 2
                    continue

                # Last attempt failed
                try:
                    err_body = response.json()
                except Exception:
                    err_body = {"text": response.text[:512]}
                raise RuntimeError(f"[!] LLM request failed: {response.status_code} - {err_body}")

            except requests.RequestException as e:
                # Network/transient error: backoff and retry
                if attempt < max_retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise RuntimeError(f"[!] LLM request exception after retries: {e}")

    def generate_seeds(self, project, driver, seed_path):
        cmd = " ".join([driver.driver] + driver.args)
        prompt = self.get_sg_prompt(project.to_string(), cmd, driver.description)
        #print(prompt)
        try:
            content = self._post_prompt(prompt)
            #print(content)
            return self.save_seeds(project.is_base64_encoding(), content, seed_path)
        except Exception as e:
            print(f"[!] LLM request failed: {e}")
            # Non-fatal: continue without generated seeds
            return 0

    def get_opt_values(self, cmd, opt, arg, desc, num=3) -> list:
        prompt = self.get_opt_values_prompt(cmd, opt, arg, desc, num)
        try:
            #print(prompt)
            content = self._post_prompt(prompt)
            return self.normalize_opt_values(content)
        except Exception as e:
            print(f"[!] LLM opt value generation failed for {cmd} {opt}: {e}")
            # Non-fatal: return empty so the pipeline can skip this option
            return []