"""Compatibility entry point for the bounded official RBA sampler."""
from pathlib import Path
import runpy

if __name__ == '__main__':
    runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/acquire_rba_sample.py'), run_name='__main__')
