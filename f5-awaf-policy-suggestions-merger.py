import requests 
import urllib3
import json
import re
import argparse
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class F5PolicySuggestionsMergerException(Exception):
    pass

class ASM:

    __device = None
    __policyId = None
    __session = None
    __policy_json = None
    __suggestions_json = None
    __merged_policy_json = None

    def __init__(self,device,username,password):

        self.__device = device

        self.__session = requests.Session()
        self.__session.verify=False
        self.__session.auth = (username,password)

    def __asm_get_policyid_by_name(self,policyName):
        
        url = "https://%s/mgmt/tm/asm/policies?$select=name,id,fullPath" % self.__device

        try:
            resp = self.__session.get(url)
        except requests.exceptions.RequestException as error:
                raise F5PolicySuggestionsMergerException("(REQUESTS): FAILED %s" % error)

        policies = resp.json()['items']

        for policy in policies:

            if policy['fullPath'] == policyName:
                self.__policyId = policy['id'] 
                break

        if self.__policyId == None:
            raise F5PolicySuggestionsMergerException("(POLICY): No such WAF policy '%s'. Specify a valid WAF policy using the method 'set_policy'." % policyName)

    def set_policy(self,policyName):

        self.__policyName = policyName

        self.__asm_get_policyid_by_name(policyName)

    def export_policy(self):

        if self.__policyId == None:
            raise F5PolicySuggestionsMergerException("(POLICY): Specify a valid WAF policy using the method 'set_policy'.")
        
        filename = self.__policyName[1:].replace("/","-") + "." + "json"

        data = {}
        data['filename'] = filename
        data['format'] = "json"
        data['minimal'] = True
        data['policyReference'] = {}
        data['policyReference']['link'] = "https://localhost/mgmt/tm/asm/policies/%s" % (self.__policyId)

        url = "https://%s/mgmt/tm/asm/tasks/export-policy" % self.__device

        try: 
            resp = self.__session.post(url, json=data)
        except requests.exceptions.RequestException as error:
            raise F5PolicySuggestionsMergerException("(REQUESTS): FAILED %s" % error)

        taskLink = resp.json()['selfLink'].replace("localhost",self.__device)

        while True:

            try:
                resp = self.__session.get(taskLink)
            except requests.exceptions.RequestException as error:
                raise F5PolicySuggestionsMergerException("(REQUESTS): FAILED %s" % error)

            task_status = resp.json()['status']

            if task_status == "COMPLETED":
                break
        try:
            resp = self.__session.get("https://%s/mgmt/tm/asm/file-transfer/downloads/%s" % (self.__device,filename))
        except requests.exceptions.RequestException as error:
            raise F5PolicySuggestionsMergerException("(REQUESTS): FAILED %s" % error)

        self.__policy_json = resp.json()

    def export_suggestions(self):

        if self.__policyId == None:
            raise F5PolicySuggestionsMergerException("(POLICY): Specify a valid WAF policy using the method 'set_policy'.")
        
        filename = self.__policyName[1:].replace("/","-") + "." + "suggestions" + "." + "json"

        data = {}
        data['filename'] = filename
        data['format'] = "json"
        data['policyReference'] = {}
        data['policyReference']['link'] = "https://localhost/mgmt/tm/asm/policies/%s" % (self.__policyId)
        
        url = "https://%s/mgmt/tm/asm/tasks/export-suggestions/" % self.__device

        try:
            resp = self.__session.post(url, json=data)
        except requests.exceptions.RequestException as error:
            raise F5PolicySuggestionsMergerException("(REQUESTS): FAILED %s" % error)

        taskLink = resp.json()['selfLink'].replace("localhost",self.__device)

        while True:
            
            try:
                resp = self.__session.get(taskLink)
            except requests.exceptions.RequestException as error:
                raise F5PolicySuggestionsMergerException("(REQUESTS): FAILED %s" % error)

            task_status = resp.json()['status']

            if task_status == "COMPLETED":
                break

        try:
            resp = self.__session.get("https://%s/mgmt/tm/asm/file-transfer/downloads/%s" % (self.__device,filename))
        except requests.exceptions.RequestException as error:
            raise F5PolicySuggestionsMergerException("(REQUESTS): FAILED %s" % error)

        self.__suggestions_json = resp.json()

    def load_suggestions(self,filename):

        try:
            with open(filename) as file:
                self.__suggestions_json = json.load(file)
        except OSError as error:
            raise F5PolicySuggestionsMergerException("(FILE): %s" % error)

    def load_policy(self,filename):

        try:
            with open(filename) as file:
                self.__policy_json = json.load(file)
        except OSError as error:
            raise F5PolicySuggestionsMergerException("(FILE): %s" % error)

    def merge_policy_suggestions(self):

        if self.__policyId == None:
            raise F5PolicySuggestionsMergerException("(POLICY): Specify a valid WAF policy using the method 'set_policy'.")

        self.__merged_policy_json = json.loads(json.dumps(self.__policy_json))

        self.__merged_policy_json['modifications'] = self.__suggestions_json

    def import_policy_merged(self):
    
        if self.__policyId == None:
            raise F5PolicySuggestionsMergerException("(POLICY): Specify a valid WAF policy using the method 'set_policy'.")

        filename = self.__policyName[1:].replace("/","-") + "." + "json"

        url = "https://%s/mgmt/tm/asm/file-transfer/uploads/%s" % (self.__device,filename)

        headers = {"Content-Range": "0-99/100"}

        try:
            resp = self.__session.post(url, json=self.__merged_policy_json, headers=headers)
        except requests.exceptions.RequestException as error:
            raise F5PolicySuggestionsMergerException("(REQUESTS): FAILED %s" % error)

        message = resp.json()['message']

        m = re.search('buffer length (.*)',message)

        size = int(m.group(1))
        
        headers = {"Content-Range": "0-%d/%d" % (size-1,size)}

        try:
            resp = self.__session.post(url, json=self.__merged_policy_json,headers=headers)
        except requests.exceptions.RequestException as error:
            raise F5PolicySuggestionsMergerException("(REQUESTS): FAILED %s" % error)

        url = "https://%s/mgmt/tm/asm/tasks/import-policy/" % (self.__device)

        data = {}
        data['filename'] = filename
        data['policy'] = {}
        data['policy']['fullPath'] = self.__policyName

        resp = self.__session.post(url, json=data)

        # apply the policy which was imported
        url = "https://%s/mgmt/tm/asm/tasks/apply-policy/" % (self.__device)

        data = {}
        data['policy'] = {}
        data['policy']['fullPath'] = self.__policyName

        try:
            resp = self.__session.post(url, json=data)
        except requests.exceptions.RequestException as error:
                raise F5PolicySuggestionsMergerException("(REQUESTS): FAILED %s" % error)

    def save_policy(self,dirpath):
        
        if self.__policyId == None:
            raise F5PolicySuggestionsMergerException("(POLICY): Specify a valid WAF policy using the method 'set_policy'.")

        filename = self.__policyName[1:].replace("/","-") + "." + "policy" + "." + "json"

        try: 
            with open("%s/%s" % (dirpath,filename), "w") as policy:
                policy.write(json.dumps(self.__policy_json, indent=2, sort_keys=False))
        except OSError as error:
            raise F5PolicySuggestionsMergerException("(FILE): %s" % error)

    def save_suggestions(self,dirpath):

        if self.__policyId == None:
            raise F5PolicySuggestionsMergerException("(POLICY): Specify a valid WAF policy using the method 'set_policy'.")

        filename = self.__policyName[1:].replace("/","-") + "." + "suggestions" + "." + "json"

        try:
            with open("%s/%s" % (dirpath,filename), "w") as suggestions:
                suggestions.write(json.dumps(self.__suggestions_json, indent=2, sort_keys=False))
        except OSError as error:
            raise F5PolicySuggestionsMergerException("(FILE): %s" % error)

    def save_merged_policy(self,dirpath):

        if self.__policyId == None:
            raise F5PolicySuggestionsMergerException("(POLICY): Specify a valid WAF policy using the method 'set_policy'.")

        filename = self.__policyName[1:].replace("/","-") + "." + "policymerged" + "." + "json"

        try:
            with open("%s/%s" % (dirpath,filename), "w") as mergedPolicy:
                mergedPolicy.write(json.dumps(self.__merged_policy_json, indent=2, sort_keys=False))
        except OSError as error:
            raise F5PolicySuggestionsMergerException("(FILE): %s" % error)

def main():
    
    parser = argparse.ArgumentParser(description = 'A small script to export a WAF policy and all its suggestions, merge them and then import the policy again')

    parser.add_argument('--device', type=str, required=True)
    parser.add_argument('--username', type=str, required=True)
    parser.add_argument('--password', type=str, required=True)
    parser.add_argument('--policy', type=str, required=True)
    parser.add_argument('--action', type=str, required=False, default="merge-save", choices=['only-save-suggestions', 'only-save-policy', 'merge-save','merge-save-import','merge-import'])
    parser.add_argument('--suggestionsfile', type=str, required=False, default="nofile")
    parser.add_argument('--policyfile', type=str, required=False, default="nofile")
    parser.add_argument('--dirpath', '-o', type=str, required=False, default=".")

    args = parser.parse_args()

    device = args.device
    username = args.username
    password = args.password
    policy = args.policy
    action = args.action
    suggestionsfile = args.suggestionsfile
    policyfile = args.policyfile
    dirpath = args.dirpath


    asm = ASM(device,username,password)

    if action == "only-save-suggestions":

        try:
            asm.set_policy(policy)
            asm.export_suggestions()
            asm.save_suggestions(dirpath)

        except F5PolicySuggestionsMergerException as error:
            print("ERROR %s" % error, file=sys.stderr)
            sys.exit(1)

        sys.exit(0)

    if action == "only-save-policy":

        try:
            asm.set_policy(policy)
            asm.export_policy()
            asm.save_policy(dirpath)

        except F5PolicySuggestionsMergerException as error:
            print("ERROR %s" % error, file=sys.stderr)
            sys.exit(1)

        sys.exit(0)


    if action == "merge-save":

        try:
            asm.set_policy(policy)

            if policyfile == "nofile":
                asm.export_policy()
            else:
                asm.load_policy(policyfile)

            if suggestionsfile == "nofile":
                asm.export_suggestions()
            else:
                asm.load_suggestions(suggestionsfile)

            asm.merge_policy_suggestions()
            asm.save_policy(dirpath)
            asm.save_suggestions(dirpath)
            asm.save_merged_policy(dirpath)
        
        except F5PolicySuggestionsMergerException as error:
            print("ERROR %s" % error, file=sys.stderr)
            sys.exit(1)

        sys.exit(0)

    if action == "merge-save-import":

        try:
            asm.set_policy(policy)

            if policyfile == "nofile":
                asm.export_policy()
            else:
                asm.load_policy(policyfile)

            if suggestionsfile == "nofile":
                asm.export_suggestions()
            else:
                asm.load_suggestions(suggestionsfile)

            asm.merge_policy_suggestions()
            asm.save_policy(dirpath)
            asm.save_suggestions(dirpath)
            asm.save_merged_policy(dirpath)
            asm.import_policy_merged()

        except F5PolicySuggestionsMergerException as error:
            print("ERROR %s" % error, file=sys.stderr)
            sys.exit(1)

        sys.exit(0)

    if action == "merge-import":

        try:
            asm.set_policy(policy)

            if policyfile == "nofile":
                asm.export_policy()
            else:
                asm.load_policy(policyfile)

            if suggestionsfile == "nofile":
                asm.export_suggestions()
            else:
                asm.load_suggestions(suggestionsfile)

            asm.merge_policy_suggestions()
            asm.import_policy_merged()

        except F5PolicySuggestionsMergerException as error:
            print("ERROR %s" % error, file=sys.stderr)
            sys.exit(1)

        sys.exit(0)

if __name__ == "__main__":
    main()