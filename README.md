# Passive company scanner
to be used for educational purposes only
this notebook is an experiment, take it as it is

# Requirements
- Shodan membership https://www.shodan.io/store/member for search filters function
- Shodan API key
- Censys API key
# installation
ubuntu/debian:

    apt-get install python3-notebook
    pip install -r requirements.txt
    
# start and configuration
from terminal:

    jupyter-notebook

# configure

 - go to the link like:
http://127.0.0.1:8888/?token=d1aed6f53b4554463912ade1db457a9aa068b6d2acb29a5c
 - open "company_check.ipynb"
 - in the second block of the notebook insert the api UID & Secret of censys and the api key of shodan
 - in the target_regex variable insert the name of the company using the regex syntax:
default: r'\b company ' (method used to avoid false positives)

# execute
In the browser in the notebook go to "Kernel -> Restart & Run All"

*(about bugs and errors:  if the shodan api does not work, consider that this is needed https://www.shodan.io/store/member moreover, if it does not find results from the assigned target, it will go into error)*
