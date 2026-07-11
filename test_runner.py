import subprocess
from key_generator import load_or_create_master_key, generate_license_key

def main():
    mk = load_or_create_master_key()
    key = generate_license_key(mk)
    print(f"Generated Key: {key}")
    
    # We provide the key, then 'env' to print environment, then 'exit' to quit the CLI shell
    inputs = f"{key}\nenv\nexit\n"
    
    process = subprocess.Popen(
        ["python", "slovic.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    stdout, stderr = process.communicate(input=inputs)
    
    if "[+] Key accepted. Loading toolkit..." in stdout:
        print("[SUCCESS] Key was accepted and toolkit loaded.")
    else:
        print("[FAIL] Toolkit did not load properly.")
        print(stdout)
        print(stderr)
        
    if "Session variables:" in stdout:
        print("[SUCCESS] Found CLI output.")
    else:
        print("[FAIL] CLI output not found.")

if __name__ == "__main__":
    main()
