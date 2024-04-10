import requests
import json


response = requests.post('localhost:8080', files = {"form_field_name": test_file})
print(response.content)