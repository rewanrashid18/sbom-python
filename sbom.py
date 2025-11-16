import sys
import re
import json
import csv
import subprocess
from pathlib import Path 

def get_cmd_arg():
    """Gets and checks if the supplied command line argument is valid"""

    if len(sys.argv) != 2:
        print(f"Error: this command take only 1 command line input but {len(sys.argv) - 1} were given")
        sys.exit(1)

    cmd_arg = str(sys.argv[1]) # Directory path
    return cmd_arg

def get_all_repos(dir_path):
    """Returns an object with all retrieved repositories separated by type in order"""

    directory = Path(dir_path) 

    repos = {
        "requirements_repos": [],
        "package_json_repos": []
    }
    for repo in directory.iterdir():
        if repo.is_dir(): # Check if directory is a repo ie. contains package or requirements
            has_package_json = (repo / "package.json").exists() 
            has_requirements_txt = (repo / "requirements.txt").exists() 

            if has_requirements_txt: 
                repos["requirements_repos"].append(repo)
                
            if has_package_json:
                repos["package_json_repos"].append(repo)

    repos.get("requirements_repos", []).sort()
    repos.get("package_json_repos", []).sort()

    total_repos = len(repos.get("requirements_repos", [])) + len(repos.get("package_json_repos", []))
    print(f"Found {total_repos} repos in '{dir_path}'")
    return repos 

def git_commit_hash(repo_path): 
    """Executes a subrpocess that returns the last commit hash of the git repo"""

    try:
        cmd = ["git", "log", "--format=%H", "-n", "1"]
        commit = subprocess.run(
            cmd,
            cwd=str(repo_path), # Go to repo directory
            capture_output=True,
            text=True,
            check=True
        )

        return commit.stdout.strip()

    except subprocess.CalledProcessError as e:
        print(f"Error: executing git command in {str(repo_path)}")
        print(f"{e.stderr.strip()}")
        return "0000000000000000000000000000000000000000" # Return 40 character default string

    except FileNotFoundError:
        print("'git' is not found, cannot determine commit hash")
        return ""
    

def get_indirect_dependencies(repos):
    """Gets all indirect dependencies and returns a 2D list containing the datarows """

    indirect_dependencies = []  
    for repo_path in repos.get("package_json_repos", []):
        lock_path = repo_path / "package-lock.json"

        try:
            with open(lock_path, "r", encoding="utf-8") as f:
                lock_data = json.load(f)

        except FileNotFoundError:
            print(f"Error: package-lock.json not found at {str(repo_path / "package-lock.json")}")
            continue

        root = lock_data.get("packages", {}).get("", {})
        direct_dependencies = set(root.get("dependencies", {}).keys())

        for path, package_info in lock_data.get("packages", {}).items():
            if path == "":
                continue
            
            if package_info.get("dev") == True:
                continue

            package_name = path.split('node_modules/')[1] 
            if package_name not in direct_dependencies:
                version = package_info.get("version", "")
                commit_hash = git_commit_hash(repo_path)
                indirect_dependencies.append([package_name, version, "npm", str(lock_path), commit_hash])

    return indirect_dependencies


    

def create_sbom_data(repos):
    """Returns a 2D list with first element the category header, and subsequent elements the corresponding data"""

    DEPENDENCY_PATTERN = re.compile(r"([^<=>~]+)(\s*[<=>~]+\s*)(.*)?") # Three groups capturing name, operator and version
    sbom_data = [
        ["name", "version", "type", "path", "commit_hash"]
    ]
    
    for repo_path in repos.get("requirements_repos", []):

        requirements_path = repo_path / "requirements.txt"
        with open(requirements_path, "r", encoding="utf-8") as f:

            for line in f:
                raw_line = line.strip()

                if not raw_line or raw_line.startswith("#"): # Skip commented lines
                    continue

                dependency_line = raw_line.split("#", 1)[0].strip()

                if not dependency_line:
                    continue

                match = DEPENDENCY_PATTERN.match(dependency_line)

                if match:
                    name = match.group(1).strip()
                    operator = match.group(2)
                    version = match.group(3)

                    if version:
                        version = (operator + version).strip()  
                    else:
                        version = None 
                        
                    absolute_file_path = str(requirements_path) 
                    commit_hash = git_commit_hash(repo_path)
                    data = [name, version, "pip", absolute_file_path, commit_hash]

                    sbom_data.append(data)

    for repo_path in repos.get("package_json_repos", []):

        package_json_path = repo_path / "package.json"
        with open(package_json_path, "r", encoding="utf-8") as f:

            py_obj = json.load(f)

            dependencies = py_obj.get("dependencies", {})
            name_version_pairs = dependencies.items()

            for name, version in name_version_pairs:
                absolute_file_path = str(package_json_path) 
                commit_hash = git_commit_hash(repo_path)
                data = [name, version, "npm", absolute_file_path, commit_hash]

                sbom_data.append(data)

    indirect_dependencies = get_indirect_dependencies(repos)

    sbom_data.extend(indirect_dependencies)

    return sbom_data

def create_sbom_csv(dir_path, sbom_data):
    """Takes as input the directory and the 2D data list and creates a sbom.csv in the directory"""

    if len(sbom_data) < 2: # If there are no dependencies don't create SBOM
        print("Terminating CSV SBOM creation...")
        return

    save_path = Path(dir_path) / "sbom.csv"
    with open(save_path, "w", encoding="utf-8") as csvfile:
        csv_writer = csv.writer(csvfile, delimiter=",", lineterminator="\n")

        for row in sbom_data:
            csv_writer.writerow(row)

        print(f"Saved SBOM in CSV format to '{str(save_path)}'")

def create_sbom_json(dir_path, sbom_data):
    """Takes as input the directory and the 2D data list and creates an sbom.json in the directory"""
    
    if len(sbom_data) < 2:
        print("Terminating JSON SBOM creation...")
        return

    save_path = Path(dir_path) / "sbom.json"
    with open(save_path, "w", encoding="utf-8") as jsonfile:
        json_data = []

        headers = sbom_data[0] 
        data_rows = sbom_data[1:]
        for row in data_rows:
            entry = dict(zip(headers, row))
            json_data.append(entry)

        json.dump(json_data, jsonfile, indent=2)

        print(f"Saved SBOM in JSON format to '{str(save_path)}'")

if __name__ == "__main__": 
    dir_path = get_cmd_arg()
    repos = get_all_repos(dir_path)
    sbom_data = create_sbom_data(repos)

    create_sbom_csv(dir_path, sbom_data)
    create_sbom_json(dir_path, sbom_data)
