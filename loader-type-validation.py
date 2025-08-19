import os
import argparse
import pandas as pd
import re
from tqdm import tqdm
import swifter  # pip install swifter
from concurrent.futures import ProcessPoolExecutor, as_completed

# === Input/Output folders ===
loaders_dir = "loaders"
mismatch_dir = "mismatches"
os.makedirs(mismatch_dir, exist_ok=True)

# === Matching logic ===
def get_new_type(row):
    def lower(val):
        return str(val).lower() if pd.notnull(val) else ''

    def rlike(val, pattern):
        return re.search(pattern, str(val), flags=re.IGNORECASE) is not None

    internal_contributor = lower(row.get("internal_contributor", ""))
    host_name = lower(row.get("host_name", ""))
    cloud_native_type = row.get("cloud_native_type", None)

    if (internal_contributor in ['unknown', 'other', ''] or pd.isnull(row.get("internal_contributor"))) and \
       host_name == '' and pd.isnull(cloud_native_type):
        return 'Unknown'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:network device(?:s)?|cisco ios|fortinet fortios|juniper junos|sonicos|pulse secure|big ip|pulse connect|netscreen|netscaler|router(?:s)?|huawei ar151|ironport)(?![A-Za-z0-9])") or \
       rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:infoblox|sip device|avaya sip device|avaya ip phone|avaya voip|biometric|switch(?:es)?|arista|check point gaia|aironet|cisco|juniper|pan-os|panos|palo alto|pfsense|forti|fortios|fortimanager|fortinet|fortigate|polycom|blue coat|mikrotik|asterisk|okilan|qnap|vxworks|extremexos|f5 networks|f5 big-ip|big-ip ltm|local traffic manager|ribbon session border controller|ribbon sbc|openwrt|jnpr|freebsdjnpr|citrix|simatic net|arista eos|brocade|fabric|timos|alcatel|acme|cabletron|ciena|covaro|extreme networks|fibrenet|lightwave|microchip|net optics|nextep|nortel|oneaccess|optix|powertel|telstra|alteon|firewall(?:s)?|apc network|aruba|buffalo terastation|emcnetwork|network camera|network cameras|web\s*gateway|networking\s*switch(?:es)?|axis\s*.*network\s*camera|axis\s*m\d{4})(?![A-Za-z0-9])|.*\.sbc\."):
        return 'Network Device' 

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:member\s*server|standalone\s*server|dedicated\s*server|application\s*server|mail\s*server|dns\s*server|web|file|db|dhcp)\s*server(?![A-Za-z0-9])|.*(?<![A-Za-z0-9])(?:ibm as/400|red hat enterprise linux|dell remote access|domain controller|hp-ux 11|hp tru64|aix|ubuntu server|solaris|openvms|as/400|ubuntu / tiny core linux|oracle|datacenter|amazon linux|suse|red hat|i86pc|ilom|hp ilo|hp integrated lights-out|euleros|hp ux|sql|teradata|sunos|active directory|linux kernel|redhat|proliant|poweredge|idrac|nutanix|super micro|centos|netapp|hp onboard administrator|ppc linux|i686 linux|rocky linux|freebsd)(?![A-Za-z0-9])|.*(?<![A-Za-z0-9])(?:x86_64 linux/5\.15\.0-94-generic|unix/samba 3\.6\.3-|generic linux 2\.6\.18)(?![A-Za-z0-9])") \
       and not rlike(internal_contributor, r".*(?<![A-Za-z0-9])workstation(?![A-Za-z0-9])"):
        return 'Server'

    # Additional server detection for values containing "Server" keyword
    if rlike(internal_contributor, r".*server(?!less)"):
        return 'Server'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:r2|2003|2008|2012|2016|2022)\s*windows(?![A-Za-z0-9])|.*(?<![A-Za-z0-9])windows\s*(?:nt|2000)(?![A-Za-z0-9])|.*(?<![A-Za-z0-9])windows\s*server\s*(?:r2|2003|2008|2012|2016|2022)(?![A-Za-z0-9])") \
       and 'server' in internal_contributor:
        return 'Server'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])windows\s*2000\s*lan\s*manager(?![A-Za-z0-9])|.*(?<![A-Za-z0-9])(?:linux\s*2\.6|linux\s*2\.4)(?![A-Za-z0-9])"):
        return 'Server'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])enterprise(?![A-Za-z0-9])") and not rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:windows|android|chromeos|chrome)(?![A-Za-z0-9])"):
        return 'Server'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])domain\s*controller(?![A-Za-z0-9])|.*(?<![A-Za-z0-9])domain\s*controllers(?![A-Za-z0-9])"):
        return 'Server'

    # Specific detection for SMC Incorporated IPMI
    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])smc incorporated ipmi(?![A-Za-z0-9])"):
        return 'Server'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:windows\s*(?:7|8|10|11|rt))(?![A-Za-z0-9])") and \
       not rlike(internal_contributor, r".*2019.*"):
        return 'Workstation'

    # Specific detection for Windows RT
    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])windows\s*rt(?![A-Za-z0-9])"):
        return 'Workstation'

    if (rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:ipad|ipod|iphone|android(?:\s*for\s*work|enterprise)?|androidforwork|android\s*for\s*work|android\s*enterprise|androidenterprise|tizen|tecno ch7n|lenovo tb-|sm-|moto|vog-|eml-|ane-|mar-|vivo|tecno|swift|nokia|pixel|nexus|oneplus|mi|asus_|phone|poco|realme|one-plus|tablet)(?![A-Za-z0-9])") and \
        not rlike(internal_contributor, r".*(?<![A-Za-z0-9])windows(?![A-Za-z0-9])")) or \
        rlike(internal_contributor, r".*(?<![A-Za-z0-9])ios(?![A-Za-z0-9])"):
        return 'Mobile'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])printer(?![A-Za-z0-9])") or \
       rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:xerox|canon|hp laser|hp jetdirect|samsung x4220r|varioprint|sato network printing version|lexmark|lantronix|kyocera|hp ethernet|ricoh printer|epson printer)(?![A-Za-z0-9])"):
        return 'Printer'

    if rlike(str(cloud_native_type), r".*(?<![A-Za-z0-9])(?:instance|virtual machine)(?![A-Za-z0-9])") or \
       rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:virtual_machine|aws instance|azure instance|gcp instance)(?![A-Za-z0-9])"):
        return 'Virtual Machine'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])darwin(?![A-Za-z0-9])"):
        return 'Workstation'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:windows\s*(?:xp|vista)|desktop|workstation|workstations|vdi|wvd)(?![A-Za-z0-9])") and \
       not rlike(internal_contributor, r".*2019.*"):
        return 'Workstation'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:macos|macmdm|mac\s*mdm|mac\s*os)(?![A-Za-z0-9])"):
        return 'Workstation'

    if (rlike(internal_contributor, r".*(?<![A-Za-z0-9])linux(?![A-Za-z0-9])") and not rlike(host_name, r"(?i).*(router|firewall|switch|gateway|modem|access[\s\-_]*point)")) or \
        rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:laptop|virtual host|vdi|mac|windows|endpoint|debian|ubuntu|tablet)(?![A-Za-z0-9])") or \
       (rlike(internal_contributor, r".*(?<![A-Za-z0-9])other(?![A-Za-z0-9])") and rlike(host_name, r".*(?<![A-Za-z0-9])vdi(?![A-Za-z0-9])")) or \
       rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:optiplex|book|hp elite|hp\s*elitedesk|prodesk|pavilion|surface|compaq|latitude|travelmate|gaming|veriton|precision|presario|predator|inspiron|chromeos|chrome|vostro|mini pc|extensa|proone|sff|tecra|thin|alienware|all-in-one pc|acer|aspire|microtower|spectre|nitro|ideapad|bravo|rog|hp pro|hp\s*probook|dell xps 13|dell xps 15|lenovo legion|lenovo yoga|haiku|parrot|webos)(?![A-Za-z0-9])|.*(?<![A-Za-z0-9])asus(?![A-Za-z0-9])(?!_)") or \
       rlike(host_name, r".*(?<![A-Za-z0-9])(?:laptop|workstation)(?![A-Za-z0-9])"):
        return 'Workstation'

    # Specific detection for Wyse ThinOS
    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])wyse\s*thinos(?![A-Za-z0-9])"):
        return 'Workstation'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])virtual\s*machine(?![A-Za-z0-9])"):
        return 'Virtual Machine'

    if rlike(internal_contributor, r".*Unknown Virtual Machine Microsoft Corporation"):
        return 'Virtual Machine'

    # Additional check for HP EliteBook, HP notebook, and VivoBook patterns
    if rlike(internal_contributor, r"(?i)(?<![A-Za-z0-9])(?:hp[\s_]+elitebook|hp[\s_]+\d+[\s_]+g\d+[\s_]+notebook|vivo(?:book)?(?:[\s_]+asus(?:laptop)?)?[\s_]*laptop)(?![A-Za-z0-9])"):
        return 'Workstation'

    if rlike(internal_contributor, r".*(?<![A-Za-z0-9])(?:vmware|esx|esxi|vsphere|vcenter)(?![A-Za-z0-9])"):
        return 'Hypervisor'

    # Check hostname for networking device patterns
    if rlike(host_name, r"(?i).*(router|firewall|switch|gateway|modem|access[\s\-_]*point)"):
        return 'Network Device'

    if rlike(host_name, r".*android.*"):
        return 'Mobile'

    return 'Unknown'

# === Worker Function ===
def process_file(file_name):
    file_path = os.path.join(loaders_dir, file_name)
    df = pd.read_csv(file_path)

    if "type" not in df.columns:
        return {"file": file_name, "total": 0, "match": 0, "mismatch": 0}

    # Use swifter to parallelize get_new_type
    df["new_type"] = df.swifter.apply(get_new_type, axis=1)
    df["match"] = df["type"].str.lower().fillna("unknown") == df["new_type"].str.lower().fillna("unknown")

    total = len(df)
    match_count = df["match"].sum()
    mismatch_count = total - match_count

    mismatches = df[~df["match"]].copy()

    # Keep these fields in the output
    columns_to_include = [
        "p_id", "os", "type", "host_name", "internal_contributor", "cloud_native_type", "new_type", "match"
    ]
    # Make sure all required columns exist
    available_columns = [col for col in columns_to_include if col in mismatches.columns]

    if not mismatches.empty:
        mismatch_path = os.path.join(mismatch_dir, f"mismatch_{file_name}")
        mismatches[available_columns].to_csv(mismatch_path, index=False)

    return {"file": file_name, "total": total, "match": match_count, "mismatch": mismatch_count}

# === CLI & File Selection ===
def parse_cli_args():
    parser = argparse.ArgumentParser(
        description="Validate and compare inferred 'type' for loader CSV files."
    )
    parser.add_argument(
        "--files", "-f",
        nargs="+",
        help=(
            "Specific CSV files inside 'loaders/' to process. "
            "Provide as space-separated names or a single comma-separated string. "
            "Examples: -f a.csv b.csv  |  -f a.csv,b.csv"
        ),
    )
    return parser.parse_args()


def _normalize_requested_files(requested_args):
    if not requested_args:
        return None
    # Support a single comma-separated string or multiple separate values
    if len(requested_args) == 1 and ("," in requested_args[0]):
        candidates = [part.strip() for part in requested_args[0].split(",") if part.strip()]
    else:
        candidates = [part.strip() for part in requested_args if part and part.strip()]

    normalized = []
    for name in candidates:
        base_name = os.path.basename(name)
        if not base_name.lower().endswith(".csv"):
            base_name = f"{base_name}.csv"
        normalized.append(base_name)
    return normalized


def get_csv_files_to_process(files_arg):
    requested_files = _normalize_requested_files(files_arg)
    if requested_files:
        existing, missing = [], []
        for file_name in requested_files:
            candidate_path = os.path.join(loaders_dir, file_name)
            if os.path.isfile(candidate_path):
                existing.append(file_name)
            else:
                missing.append(file_name)
        if missing:
            print(
                f"Warning: {len(missing)} requested file(s) not found in '{loaders_dir}': "
                + ", ".join(missing)
            )
        return existing

    # Default: all CSVs with built-in exclusions
    return [
        f for f in os.listdir(loaders_dir)
        if f.endswith(".csv")
        and all(excl not in f.lower() for excl in ["itop", "wiz", "ms_azure_ad_devices_groups", "all_loader", "all_loaders"])
    ]

# === Main Execution ===
if __name__ == "__main__":
    args = parse_cli_args()
    csv_files = get_csv_files_to_process(args.files)
    if not csv_files:
        print("No CSV files to process. Exiting.")
        raise SystemExit(0)

    results = []

    max_workers = os.cpu_count() or 4
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(process_file, file_name): file_name for file_name in csv_files}
        with tqdm(total=len(csv_files), desc="Processing files", unit="file") as progress_bar:
            for future in as_completed(future_to_file):
                file_name = future_to_file[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"file": file_name, "total": 0, "match": 0, "mismatch": 0, "error": str(exc)}
                results.append(result)
                progress_bar.set_postfix(file=file_name)
                progress_bar.update(1)


    # === Write summary to TXT ===
    summary_txt_path = "type_match_summary.txt"

    with open(summary_txt_path, "w") as f:
        f.write("Type Match Summary per File\n")
        f.write("=" * 40 + "\n\n")

        for res in results:
            f.write(f"File: {res['file']}\n")
            f.write(f"Total Rows     : {res['total']}\n")
            f.write(f"Matched        : {res['match']}\n")
            f.write(f"Mismatched     : {res['mismatch']}\n")
            f.write("-" * 30 + "\n")

    print(f"\nSummary saved to: {summary_txt_path}")

    # === Print Summary DataFrame ===
    summary_df = pd.DataFrame(results)
    print(summary_df)
