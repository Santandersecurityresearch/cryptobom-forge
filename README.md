# Cryptobom Forge Tool: Generating Comprehensive CBOMs from CodeQL Outputs

This repository houses all the tools and utilities one would need in order to parse the Multi-Repository Variant Analysis output from CodeQL runs. It is part of the wider release looking at analysing and creating Cryptographic Bill of Materials (CBOM) for [this](https://www.blackhat.com/eu-23/briefings/schedule/#the-magnetic-pull-of-mutable-protection-worked-examples-in-cryptographic-agility-36030) Blackhat talk 



## Contents

- [Quickstart](#quickstart)
  - [Excluding File Paths](#excluding-file-paths)
- [Cryptography Checker](#cryptography-checker)
  - [Analysis Output](#analysis-output)
  - [YAML Rule Structure](#yaml-rule-structure)
    - [Example Rules](#example-rules)

## Quickstart

**Prerequisites:**

* Python 3.10 or higher is essential for the proper functioning of this tool.

**Installation and Execution Steps:**

Step 1 - Acquire the Latest Release:

Visit the [releases](https://github.com/santandersecurityresearch/cryptobom-forge/releases) page to download the most recent version of Cryptobom Forge. This ensures that you have access to the latest features and security updates.

**Step 2 - Installation:**

Integrate the tool into your local Python environment using the Wheel package:

```
pip install cryptobom_forge-{VERSION}-py3-none-any.whl
```
Replace {VERSION} with the specific version number you downloaded. This step equips your environment with the necessary dependencies and modules for Cryptobom Forge.

**Step 3 - Execution**

Generate a CBOM using the following command:

```
cryptobom generate <path>
```

The <path> parameter is versatile, accepting either:

* A path to a single CodeQL output file, or
* A directory path containing multiple CodeQL outputs.

For each file, Cryptobom Forge meticulously parses the data to produce a comprehensive CBOM. This CBOM encapsulates detailed insights into the cybersecurity aspects of your project, essential for advanced security analysis.

Output Example:
Upon successful execution, you will receive a detailed CBOM, structured as follows:


```json
{
  "components": [
    {
      "bom-ref": "algorithm:md5",
      "cryptoProperties": {
        "algorithmProperties": {
          "primitive": "hash",
          "variant": "MD5"
        },
        "assetType": "algorithm",
        "detectionContext": [
          {
            "additionalContext": "    return (\n        \"https://www.gravatar.com/avatar/\"\n        f\"{hashlib.md5(email.encode('utf-8').lower()).hexdigest()}.jpg?s=80&d=wavatar\"\n    )\n",
            "filePath": "homeassistant/components/device_tracker/legacy.py",
            "lineNumbers": [1036, 1037, 1038, 1039]
          },
          {
            "additionalContext": "def _entity_unique_id(entity_id: str) -> str:\n    \"\"\"Return the emulated_hue unique id for the entity_id.\"\"\"\n    unique_id = hashlib.md5(entity_id.encode()).hexdigest()\n    return (\n        f\"00:{unique_id[0:2]}:{unique_id[2:4]}:\"\n",
            "filePath": "homeassistant/components/emulated_hue/hue_api.py",
            "lineNumbers": [740, 741, 742, 743, 744]
          }
        ]
      },
      "name": "MD5",
      "type": "crypto-asset"
    },
    {
      "bom-ref": "algorithm:sha1",
      "cryptoProperties": {
        "algorithmProperties": {
          "primitive": "hash",
          "variant": "SHA1"
        },
        "assetType": "algorithm",
        "detectionContext": [
          {
            "additionalContext": "from __future__ import annotations\n\nfrom hashlib import sha1\nimport logging\nimport os\n",
            "filePath": "homeassistant/components/demo/mailbox.py",
            "lineNumbers": [2, 3, 4, 5, 6]
          },
          {
            "additionalContext": "        \"\"\"Generate a cache key for a message.\"\"\"\n        options_key = _hash_options(options) if options else \"-\"\n        msg_hash = hashlib.sha1(bytes(message, \"utf-8\")).hexdigest()\n        return KEY_PATTERN.format(\n            msg_hash, language.replace(\"_\", \"-\"), options_key, engine\n",
            "filePath": "homeassistant/components/tts/__init__.py",
            "lineNumbers": [573, 574, 575, 576, 577]
          }
        ]
      },
      "name": "SHA1",
      "type": "crypto-asset"
    },
    {
      "bom-ref": "algorithm:sha256",
      "cryptoProperties": {
        "algorithmProperties": {
          "primitive": "hash",
          "variant": "SHA256"
        },
        "assetType": "algorithm",
        "detectionContext": [
          {
            "additionalContext": "                \"duration\": entry[\"duration\"],\n            }\n            sha = hashlib.sha256(str(entry).encode(\"utf-8\")).hexdigest()\n            msg = (\n                f\"Destination: {entry['dest']}\\n\"\n",
            "filePath": "homeassistant/components/asterisk_cdr/mailbox.py",
            "lineNumbers": [53, 54, 55, 56, 57]
          },
          {
            "additionalContext": "def hash_from_url(url: str):\n    \"\"\"Hash url to create a unique ID.\"\"\"\n    return hashlib.sha256(url.encode(\"utf-8\")).hexdigest()\n",
            "filePath": "homeassistant/components/nightscout/utils.py",
            "lineNumbers": [5, 6, 7]
          }
        ]
      },
      "name": "SHA256",
      "type": "crypto-asset"
    }
  ],
  "dependencies": [
    {
      "ref": "algorithm:md5"
    },
    {
      "ref": "algorithm:sha1"
    },
    {
      "ref": "algorithm:sha256"
    },
    {
      "dependsOn": ["algorithm:md5", "algorithm:sha1", "algorithm:sha256"],
      "ref": "home-assistant/core"
    }
  ],
  "metadata": {
    "component": {
      "bom-ref": "home-assistant/core",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/home-assistant/core"
        }
      ],
      "name": "core",
      "type": "application"
    },
    "timestamp": "2023-10-30T16:47:12.165802+00:00",
    "tools": [
      {
        "externalReferences": [
          {
            "type": "build-system",
            "url": "https://github.com/CycloneDX/cyclonedx-python-lib/actions"
          },
          {
            "type": "distribution",
            "url": "https://pypi.org/project/cyclonedx-python-lib/"
          },
          {
            "type": "documentation",
            "url": "https://cyclonedx.github.io/cyclonedx-python-lib/"
          },
          {
            "type": "issue-tracker",
            "url": "https://github.com/CycloneDX/cyclonedx-python-lib/issues"
          },
          {
            "type": "license",
            "url": "https://github.com/CycloneDX/cyclonedx-python-lib/blob/main/LICENSE"
          },
          {
            "type": "release-notes",
            "url": "https://github.com/CycloneDX/cyclonedx-python-lib/blob/main/CHANGELOG.md"
          },
          {
            "type": "vcs",
            "url": "https://github.com/CycloneDX/cyclonedx-python-lib"
          },
          {
            "type": "website",
            "url": "https://cyclonedx.org"
          }
        ],
        "name": "cyclonedx-python-lib",
        "vendor": "CycloneDX",
        "version": "4.2.2"
      },
      {
        "name": "CodeQL",
        "vendor": "GitHub",
        "version": "2.14.3"
      }
    ]
  },
  "serialNumber": "urn:uuid:7b666731-bd55-4ce9-805b-ba0e1ff82b21",
  "version": 1,
  "$schema": "https://raw.githubusercontent.com/IBM/CBOM/main/bom-1.4-cbom-1.0.schema.json",
  "bomFormat": "CBOM",
  "specVersion": "1.4-cbom-1.0"
}
```

By default, the output will be printed to `stdout`. You can alternatively write the output to a file using
`--output-file` or `-o`.

```shell
$ cryptobom generate <path> --output-file cbom.json
```

### Excluding File Paths

You can optionally specify a regex string to ignore findings in files that match that path, using `--exclude` or `-e`.
The complete file path must match in order for findings to be excluded.

For example, you may wish to exclude findings in test files:

```shell
$ cryptobom generate <path> --exclude '(.*/)?test(s)?.*'
```

## Cryptography Checker - Enhanced Cryptography Compliance Analysis

**Overview:**

*Cryptocheck* is designed to automate the process of cryptography compliance analysis. It integrates two distinct inputs to generate a SARIF (Static Analysis Results Interchange Format) file, detailing the findings from a comprehensive rule check against the CBOM contents. This approach offers a streamlined and precise method for ensuring cryptographic best practices in your codebase.

### Inputs:

**CBOM (Cybersecurity Bill of Materials):**

This input is derived from the parser of SARIF files generated by CodeQL. The CBOM provides an exhaustive inventory of all cybersecurity-related components in your project, including libraries, dependencies, and associated vulnerabilities. This comprehensive overview serves as the foundation for the subsequent rule checks.

**Rules File (rules.yml):**

A YAML-formatted file, typically named rules.yml, contains a set of predefined rules focused on cryptography compliance. These rules are crafted to evaluate various aspects of cryptographic implementation, such as key lengths, algorithms, and encryption protocols. The flexibility of the YAML format allows for easy updates and customization of the rule set to align with evolving best practices and organizational policies.

### Output:

**SARIF File:**

The script processes the CBOM against the set of rules in rules.yml and outputs its findings in a SARIF file. This file includes detailed information on any discrepancies, potential vulnerabilities, or non-compliance issues related to cryptography as identified by the rules. The SARIF format ensures that the output is standardized, making it compatible with a wide range of tools for further analysis and integration into continuous integration/continuous deployment (CI/CD) pipelines.

### Analysis Output

The results from the analysis are appended as a SARIF file that has the following structure, in line with GitHub's
recommended format:

```json
{
  "$schema": "http://json.schemastore.org/sarif-2.1.0-rtm.4",
  "runs": [
    {
      "results": [
        {
          "level": "error",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "index": 0,
                  "uri": "contrib/openssl/pyca-cryptography/src/cryptography/hazmat/primitives/keywrap.py",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 18
                }
              }
            }
          ],
          "message": {
            "text": "AES was found operating in ECB mode. Please don't."
          },
          "ruleId": "AES in ECB mode",
          "ruleIndex": 0
        }
      ],
      "tool": {
        "driver": {
          "name": "CryptoCheck",
          "rules": [
            {
              "id": "AES in ECB mode",
              "properties": {
                "category": "function",
                "problem.severity": "error",
                "security-severity": 9.0,
                "tags": ["cryptography"]
              },
              "shortDescription": {
                "text": "AES was found operating in ECB mode. Please don't."
              }
            }
          ]
        }
      }
    }
  ],
  "version": "2.1.0"
}
```

### YAML Rule Structure

Each YAML file has a list of objects with the following structure:

- Each rule requires a `name`
- Each rule requires a `detection` object that has two sub-objects
  - `severity` - a number from 1 to 10, taken as a mapping for vulnerabilities (critical: >=9.0, high: 7.0 - 8.9,
    medium: 4.0-6.9, low: <=3.9)
  - `description` - a string detailing a summary of what a detection means.
  - `type` - whether the detection should count as a `warning`, `error`, or `note` (these are the only valid values)
- There is an optional `default` section that has the same parameters as the `detection` section - this is used when
  there is no detection, as a means of having a default output for no detection if required.
- Each rule requires a `patterns` object, a written out tuple of the form: `(field, type, criteria)`, taken from the
  following:
  - `type` - the types of match/check, from the following:
    - `r` (regex),
    - `s` (string match by 'contains criteria string'),
    - `lt` (numeric less-than),
    - `gt` (numeric greater-than),
    - `lteq` (numeric less-than or equal to),
    - `gteq` (numeric greater-than or equal to),
    - `eq` (logical equal to),
    - `neq` (logical not equal to)
  - `field` - the fields that the check applies to, must be one of the following:
    - `algo` - the variant algorithm
    - `keylen` - the key length of the variant, if known
    - `mode` - the mode of the cipher variant, if known
    - `padding` - the padding algorithm, if known
  - `criteria` - a free-form field for the check criteria (string, regex, or numeric as required)

**NOTE** - the tuples for `patterns` must have enclosing string single quote marks in order to be parsed by the script.
This is because they are parsed by `ast.literal_eval`, which requires them to find a valid tuple for the rule pattern
components.

#### Example Rules

The following rule detects MD5, and sets a default if nothing is found to be a problem:

```yaml
- name: MD5-detect
  default:
    type: note
    severity: 0
    description: MD5 was not found! Which is a huge relief...
  detection:
    type: error
    severity: 9.0
    description: MD5 was detected, which is a deprecated hashing algorithm that is prone to collisions, and should not be used.
  patterns:
    - ('algo', 'r', '(?i)md5')
```

or for AES in CBC mode:

```yaml
- name: AES in CBC mode
  detection:
    type: warning
    severity: 5.0
    description: AES was found operating in CBC mode, which will need manual review to determine if it is implemented safely.
  patterns:
    - ('algo', 'eq', 'AES')
    - ('mode', 'eq', 'CBC')
```

The format for the output can be found in the above extract from a SARIF output.


## Ongoing Development & The Community

The need for adaptable and robust cryptographic solutions has never been greater. This project aims to address these challenges by developing tools and methodologies that can quickly and efficiently adapt to new cryptographic standards and threats.

We are seeking contributors who are passionate about cryptography, security engineering, and the development of future-proof cryptographic systems. Whether you have ideas for new features, improvements to existing ones, or strategies to enhance the tool's accessibility and usability, your input is invaluable. 

We'd love to hear issues or accept pull requests to make it better. 


## Who Is Behind It?

This was developed by Emile El-qawas (@emilejq) of the Santander UK Security Engineering team with help from Mark Carney (@unprovable) and Daniel Cuthbert (@danielcuthbert) of Santander's Cyber Security Research (CSR) team as part of our Blackhat EU 2023 research release. 
