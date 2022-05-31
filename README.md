# f5-awaf-policy-suggestions-merger

This is a small script which can be used to automate/facilitate the process of building an ASM security policy.

The script leverages the BIG-IP **iControl REST API** and the **Declarative WAF REST API** to facilitate the process of merging an ASM policy with all its learning suggestions in an attempt the generate a more stable policy (which will result in less false positives when put in production). 

This tool must be used only when all traffic reaching your ASM security policy is valid/trusted. Some scenarios include:

    1. Automated tests in a CI/CD pipeline.
    2. Manual tests by a team (e.g QA team).

In both scenarios is a **MUST-HAVE** that all traffic reaching the application (and ASM security policy) is valid traffic (non-attack traffic). 

**The script will work only in BIG-IP version 16.X.**

## Usage

```
usage: f5-awaf-policy-suggestions-merger.py [-h] --device DEVICE --username USERNAME --password PASSWORD --policy POLICY [--action {only-save-suggestions,only-save-policy,merge-save,merge-save-import,merge-import}] [--suggestionsfile SUGGESTIONSFILE]
                                            [--policyfile POLICYFILE] [--dirpath DIRPATH]

A small script to export a WAF policy and all its suggestions, merge them and then import the policy again

optional arguments:
  -h, --help            show this help message and exit
  --device DEVICE
  --username USERNAME
  --password PASSWORD
  --policy POLICY
  --action {only-save-suggestions,only-save-policy,merge-save,merge-save-import,merge-import}
  --suggestionsfile SUGGESTIONSFILE
  --policyfile POLICYFILE
  --dirpath DIRPATH, -o DIRPATH
  ```

## Options

| Argument | Description | Required | Default |
|----------|-------------|----------|---------|
| --device | BIG-IP IP address | Yes | No |
| --username | Admin username for BIG-IP | Yes | No | 
| --password | Admin password for BIG-IP | Yes | No | 
| --policy | ASM policy name (full path: /\<partition>/\<policy name>). | Yes | No |
| --action | The **operation mode** of the script.| No | merge-save |
| --suggestionsfile | Specify a *suggestions file* to be used instead of retrieve the learning suggestions from BIG-IP. You use this option when you want to customize the suggestions before merging them with ASM policy. | No | No |
| --policyfile | Specify a *ASM policy file* to be used instead of retrieve the ASM policy from BIG-IP. You use this option when you want to customize the ASM policy before merging with its learning suggestions. | No | No |

### Operation modes

| Mode | Description | Use case |
|------|-------------|----------|
| only-save-suggestions | This mode will only download the *learning suggestions* in a JSON format and save them in current directory or in a directory specified by the option *--dirpath*.| You use this option when you want to customize the *learning suggestions* before the merging with the ASM policy.|
| only-save-policy | This mode will only download the *ASM policy* in a JSON format and save them in current directory or in a directory specified by the option *--dirpath*.| You use this option when you want to customize the *ASM policy* before the merging with its *learning suggestions*.|
| merge-save | This mode will export the *ASM policy* (or use the ASM policy specified by the option *--policyfile*), export the *learning suggestions* (or use the learning suggestions file specified by the option *--suggestionsfile*), and then merge them. The three following files will be save in the current directory or in the directory specified by the option *--dirpath*: a *ASM policy* file (extension *.policy.json*), a *learning suggestions* file (extension *.suggestions.json*) and a *merged policy* file (extension *.mergedpolicy.json*).| This is a non-intrusive mode that you can use to check the *ASM merged policy* before the actual import.|
| merge-save-import | Do the same that the operation mode **merge-save** but with a aditional step of import the *ASM merged policy* in the BIG-IP | Use this option when you sure that you import the *ASM merged policy* in the BIG-IP. | 
| merge-import | Do the same that the operation mode **merge-save-import** but without saving the files in the local system.| Use this option when you want to merge the current ASM policy with all its suggestions without saving them in the local filesystem.| 

## Scenarios

### Scenario 1 (fully automated)

The script will export the ASM policy, export the learning suggestions, and then merge them. The ASM merged policy will be upload, imported and applied on the BIG-IP.

```
python f5-awaf-policy-suggestions-merger.py --device "X.X.X.X" --username "admin" --password "XXXXXXX" --policy "/Common/asmpolicy_dvwa" --action merge-import
```

Alternatively you can use the action **merge-save-import** to have the *ASM policy* file, *learning suggestions* file and *ASM merged policy* file save on the current directory or in a directory specified by the option *--dirpath*.

### Scenario 2 (semi automated, customized **ASM policy file**)

This scenario is comprised of three steps:

1. Download the **ASM policy file**:

```
python f5-awaf-policy-suggestions-merger.py --device "X.X.X.X" --username "admin" --password "XXXXXXX" --policy "/Common/asmpolicy_dvwa" --action only-save-policy --dirpath tmp
```

2. Customize the **ASM policy file** (e.g. change the enforcement mode).

3. Export the learning suggestions for the policy and merge them with local (customized) **ASM policy file**. The ASM merged policy will be upload, imported and applied on the BIG-IP.

```
python f5-awaf-policy-suggestions-merger.py --device "X.X.X.X" --username "admin" --password "XXXXXXX" --policy "/Common/asmpolicy_dvwa" --action merge-import --policyfile tmp/Common-asmpolicy_dvwa.policy.json
```

### Scenario 3 (semi automated, customized **learning suggestions file**)

1. Download the **learning suggestions file**:

```
python f5-awaf-policy-suggestions-merger.py --device "X.X.X.X" --username "admin" --password "XXXXXXX" --policy "/Common/asmpolicy_dvwa" --action only-save-suggestions --dirpath tmp
```

2. Customize the **learning suggestions file** (e.g. remove learning suggestions that you are not sure about them).

3. Export the ASM policy and merge it with the local (customized) **learning suggestion file**. The ASM merged policy will be upload, imported and applied on the BIG-IP.

```
python f5-awaf-policy-suggestions-merger.py --device "X.X.X.X" --username "admin" --password "XXXXXXX" --policy "/Common/asmpolicy_dvwa" --action merge-import --suggestionsfile tmp/Common-asmpolicy_dvwa.suggestions.json
```

### Scenario 4 (semi automated, customized **ASM policy file** and **learning suggestions file**)

1. Download the **ASM policy file**:

```
python f5-awaf-policy-suggestions-merger.py --device "X.X.X.X" --username "admin" --password "XXXXXXX" --policy "/Common/asmpolicy_dvwa" --action only-save-policy --dirpath tmp
```

2. Download the **learning suggestions file**:

```
python f5-awaf-policy-suggestions-merger.py --device "X.X.X.X" --username "admin" --password "XXXXXXX" --policy "/Common/asmpolicy_dvwa" --action only-save-suggestions --dirpath tmp
```

3. Customize the **ASM policy file** (e.g. change the enforcement mode) and the **learning suggestions file** (e.g. remove learning suggestions that you are not sure about them).

4. Merge the local (customized) **ASM policy file** with the local (customized) **learning suggestions file**. The ASM merged policy will be upload, imported and applied on the BIG-IP.

```
python f5-awaf-policy-suggestions-merger.py --device "X.X.X.X" --username "admin" --password "XXXXXXX" --policy "/Common/asmpolicy_dvwa" --action merge-import --suggestionsfile tmp/Common-asmpolicy_dvwa.suggestions.json --policyfile tmp/Common-asmpolicy_dvwa.policy.json
```