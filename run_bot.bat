@echo off
set OPENBLAS_NUM_THREADS=1
set OMP_NUM_THREADS=1
python bot.py daemon
