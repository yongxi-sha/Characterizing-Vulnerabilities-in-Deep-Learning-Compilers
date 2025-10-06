import csv
import json
import os
import re
import sys
import time
import argparse
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Iterable, Optional
from urllib.parse import urlencode
import requests
from scraping.bench_adapter import BenchAdapter
from pathlib import Path

class CVEAdapter(BenchAdapter):

    def __init__(self, dataset):
        super().__init__(self, dataset)
        self.api_key="cf44acd1-1751-4091-b761-ac153f1a2b6c"
        self.url="https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.path=Path(f"results/{self.dataset}")
        self.path.mkdir(parents=True, exist_ok=True)

    def start_scraping(self):
        
        pass

    def data_parsing(self):

        pass
    
    def save(self):
        
        pass

    
