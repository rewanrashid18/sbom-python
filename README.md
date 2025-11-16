# sbom-python
**Command line tool** to generate a Software Bill of Materials for a directory containing multiple repositories.
It takes a path to a directory containing Git repositires as a command line argument and creates a **CSV** and **JSON** SBOM in the directory listing all indirect and direct dependencies.

# Setup
1. **Python 3:** To run the script a Python 3 environment is required.
2. **Git:** The `git` command must be accessible in your system's PATH as it is used in retrieving commit hashes.
The script uses only standard Python libraries, no other libraries are required.

# Usage
To use the command simply run:
```
python sbom.py /absolute/path/to/your/repos
```

# Project Assumptions
1. Repositories in directory are valid git repositories
2. All directories that containg a `package.json` also contain a `package-lock.json`
3. devDependencies are not of interest for the SBOM
