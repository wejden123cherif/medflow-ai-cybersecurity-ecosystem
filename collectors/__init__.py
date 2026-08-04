import importlib
import pkgutil
from pathlib import Path
from .base import BaseCollector

# Auto-discover and import all modules in the collectors package
# so that BaseCollector.__subclasses__() gets populated automatically.
def _discover_collectors():
    package_dir = Path(__file__).parent
    for _, module_name, _ in pkgutil.iter_modules([str(package_dir)]):
        if module_name != "base":
            importlib.import_module(f"collectors.{module_name}")

_discover_collectors()

__all__ = ["BaseCollector"]
