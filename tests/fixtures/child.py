#!/usr/bin/env python3
"""Small child-process fixture for local process-lineage tests."""

print("apolysis child fixture")

# Keep the child alive long enough for the local process-tree sampler to see it.
import time

time.sleep(0.5)
