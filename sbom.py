import sys
import re
import json
import csv
from pathlib import Path 

def get_cmd_arg():

    if len(sys.argv) != 2:
        print(f"Error: this command take only 1 command line input but {len(sys.argv) - 1} were given")
        sys.exit(1)

    cmd_arg = str(sys.argv[1])
    return cmd_arg

def get_all_repos(dir_path):

    directory = Path(dir_path) 

    repos = {
        "requirements_repos": [],
        "package_json_repos": []
    }
    for repo in directory.iterdir():
        if repo.is_dir():
            has_package_json = (repo / "package.json").exists() 
            has_requirements_txt = (repo / "requirements.txt").exists() 

            if has_requirements_txt: 
                repos["requirements_repos"].append(repo)
                
            if has_package_json:
                repos["package_json_repos"].append(repo)

    repos["requirements_repos"].sort()
    repos["package_json_repos"].sort()

    total_repos = len(repos["requirements_repos"]) + len(repos["package_json_repos"])
    print(f"Found {total_repos} repos in '{dir_path}'")
    return repos 
    

def create_sbom_data(repos):

    DEPENDENCY_PATTERN = re.compile(r"([^<=>~]+)(\s*[<=>~]+\s*)(.*)?")
    sbom_data = [
        ["name", "version", "type", "path"]
    ]
    
    for repo_path in repos["requirements_repos"]:
        with open((repo_path / "requirements.txt"), "r", encoding="utf-8") as f:

            for line in f:
                raw_line = line.strip()

                if not raw_line or raw_line.startswith("#"):
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
                        
                    absolute_file_path = repo_path / "requirements.txt"
                    data = [name, version, "pip", str(absolute_file_path)]
                    sbom_data.append(data)

    for repo_path in repos["package_json_repos"]:
        with open((repo_path / "package.json"), "r", encoding="utf-8") as f:

            json_string = f.read() 
            decoder = json.JSONDecoder()
            py_obj = decoder.decode(json_string)

            depdencencies = py_obj.get("dependencies", {})
            name_version_pairs = depdencencies.items()
            for name, version in name_version_pairs:
                absolute_file_path = repo_path / "package.json"
                data = [name, version, "npm", str(absolute_file_path)]
                sbom_data.append(data)

    return sbom_data

def create_sbom_csv(dir_path, sbom_data):

    if len(sbom_data) < 2:
        print("Terminating CSV SBOM creation...")
        return

    save_path = Path(dir_path) / "sbom.csv"
    with open(save_path, "w", encoding="utf-8") as csvfile:
        csv_writer = csv.writer(csvfile, delimiter=",", lineterminator="\n")

        for row in sbom_data:
            csv_writer.writerow(row)

        print(f"Saved SBOM in CSV format to '{str(save_path)}'")

def create_sbom_json(dir_path, sbom_data):
    
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
