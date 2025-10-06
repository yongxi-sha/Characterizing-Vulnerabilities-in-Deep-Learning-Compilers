from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

class BenchAdapter(ABC):
    """
    Abstract base class for integrating different dataset
    """

    def __init__(self, dataset:str):

        self.dataset = dataset


    @abstractmethod
    def best_cvss(metrics: Dict[str, Any] | None):
        pass

    @abstractmethod
    def collect_products_from_node(root: Dict[str, Any], products: set):
        pass
    
    @abstractmethod
    def extract_cwes(self, weaknesses: Any):
        pass
    
    @abstractmethod
    def fetch_page(self, session: Any, params: Dict[str, Any], api_key: Optional[str], retries, backoff: float) -> Dict[str, Any]:
        pass

    @abstractmethod
    def query_nvd(self, keywords: List[str], max_results: int, per_page: int, verbose:bool):
        pass 

    @abstractmethod
    def extract_products(self, configurations: Any):
        pass

    @abstractmethod
    def normalize(self, raw: list):
        pass

    @abstractmethod
    def save_json(self, data: list, path: str, append: bool = False):
        pass
    
    @abstractmethod
    def save_csv(self, data: list, path: str, append: bool = False):
        pass

    @abstractmethod
    def start_scraping(self):
        pass

    @abstractmethod
    def save(self):
        pass