from abc import ABC, abstractmethod
import numpy as np
from typing import Any, Union

class BenchAdapter(ABC):
    """
    Abstract base class for integrating different dataset
    """

    def __init__(self, dataset:str):

        self.dataset = dataset


    @abstractmethod
    def start_scraping(self):

        pass

    @abstractmethod
    def data_parsing(self):

        pass

    @abstractmethod
    def save(self):
        
        pass