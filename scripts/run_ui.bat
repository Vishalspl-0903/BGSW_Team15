@echo off
setlocal
echo Starting Bosch Software Supply Chain Guardian UI...
pushd "%~dp0\.."
python -m streamlit run ui/app.py
popd
endlocal

