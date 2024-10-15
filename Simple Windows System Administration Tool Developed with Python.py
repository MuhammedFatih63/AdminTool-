import os
import shutil
import psutil
import platform
import subprocess
import webbrowser
import requests
from bs4 import BeautifulSoup
import pyautogui

def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def main_menu():
    clear_screen()
    print("\n********** Windows System Management Console **********")
    print("1. File/Folder Operations")
    print("2. Task Manager")
    print("3. System Information")
    print("4. Disk Space Information")
    print("5. Run System Command")
    print("6. Open Browser")
    print("7. Weather")
    print("8. Virtual Machine Management")
    print("9. Network Information")
    print("10. System Logs")
    print("11. Application Management")
    print("12. User Management")
    print("13. File Search")
    print("14. Security Checks")
    print("15. Performance Monitoring")
    print("16. Task Scheduler Management")
    print("17. Printer Management")
    print("18. Exit")

def file_folder_operations_menu():
    clear_screen()
    print("\n********** File/Folder Operations **********")
    print("1. Create File/Folder")
    print("2. Delete File/Folder")
    print("3. List Files/Folders")
    print("4. Copy File/Folder")
    print("5. Move File/Folder")
    print("6. Rename File/Folder")
    print("7. Go Back")

def create_file_folder():
    path = input("Enter the path of the file/folder to create: ")
    try:
        os.makedirs(path)
        print("File/Folder created successfully.")
    except FileExistsError:
        print("File/Folder already exists.")
    except Exception as e:
        print(f"Error: {e}")

def delete_file_folder():
    path = input("Enter the path of the file/folder to delete: ")
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        print("File/Folder deleted successfully.")
    except FileNotFoundError:
        print("File/Folder not found.")
    except OSError:
        print("File/Folder could not be deleted. It may not be empty.")
    except Exception as e:
        print(f"Error: {e}")

def list_files_folders():
    path = input("Enter the path of the directory to list: ")
    try:
        print("\nContents of {}:".format(path))
        for item in os.listdir(path):
            print(item)
    except FileNotFoundError:
        print("Directory not found.")
    except Exception as e:
        print(f"Error: {e}")

def copy_file_folder():
    source = input("Enter the path of the file/folder to copy: ")
    destination = input("Enter the destination folder path: ")
    try:
        if os.path.isdir(source):
            shutil.copytree(source, os.path.join(destination, os.path.basename(source)))
        else:
            shutil.copy2(source, destination)
        print("File/Folder copied successfully.")
    except FileNotFoundError:
        print("Source file/folder not found.")
    except FileExistsError:
        print("File/Folder with the same name already exists in the destination.")
    except Exception as e:
        print(f"Error: {e}")

def move_file_folder():
    source = input("Enter the path of the file/folder to move: ")
    destination = input("Enter the destination folder path: ")
    try:
        shutil.move(source, destination)
        print("File/Folder moved successfully.")
    except FileNotFoundError:
        print("Source file/folder not found.")
    except shutil.Error as e:
        print(e)
    except Exception as e:
        print(f"Error: {e}")

def rename_file_folder():
    path = input("Enter the path of the file/folder to rename: ")
    new_name = input("Enter the new name: ")
    try:
        os.rename(path, os.path.join(os.path.dirname(path), new_name))
        print("File/Folder renamed successfully.")
    except FileNotFoundError:
        print("File/Folder not found.")
    except OSError:
        print("File/Folder could not be renamed.")
    except Exception as e:
        print(f"Error: {e}")

def task_manager():
    if platform.system() == "Windows":
        os.system("taskmgr")
    else:
        print("Task Manager is not available on this system.")

def system_information():
    clear_screen()
    print("\n********** System Information **********")
    print("Operating System:", platform.system())
    print("Version:", platform.release())
    print("Architecture:", platform.machine())
    print("Python Version:", platform.python_version())

def convert_bytes(bytes):
    if bytes == 0:
        return "0B"
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    i = 0
    while bytes >= 1024 and i < len(suffixes) - 1:
        bytes /= 1024.
        i += 1
    return "{:.2f} {}".format(bytes, suffixes[i])

def disk_space_information():
    partitions = psutil.disk_partitions()
    clear_screen()
    print("\n********** Disk Space Information **********")
    for partition in partitions:
        print("Device:", partition.device)
        print("File System Type:", partition.fstype)
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
            print("Total Size:", convert_bytes(partition_usage.total))
            print("Used Space:", convert_bytes(partition_usage.used))
            print("Free Space:", convert_bytes(partition_usage.free))
            print("Usage Percentage:", str(partition_usage.percent) + "%")
        except PermissionError:
            continue

def run_system_command():
    command = input("Enter the command to execute: ")
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        print(output)
    except subprocess.CalledProcessError as e:
        print("Error:", e.output)

def open_browser():
    url = input("Enter the URL of the website to open: ")
    webbrowser.open(url)

def weather():
    city = input("Enter the city for weather information: ")
    url = "https://www.google.com/search?q=weather+{}".format(city)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    temperature = soup.find("div", class_="BNeawe").text
    print("Weather:", temperature)

def virtual_machine_management():
    print("Virtual Machine Management is not implemented yet.")

def network_information():
    connections = psutil.net_connections()
    clear_screen()
    print("\n********** Network Information **********")
    for conn in connections:
        if conn.status == psutil.CONN_ESTABLISHED:
            print(f"Local Address: {conn.laddr.ip}:{conn.laddr.port} --> Remote Address: {conn.raddr.ip}:{conn.raddr.port}")

def system_logs():
    try:
        log_file = input("Enter the path of the log file to read: ")
        with open(log_file, 'r') as file:
            print("\n********** System Logs **********")
            for line in file:
                print(line.strip())
    except FileNotFoundError:
        print("Log file not found.")
    except PermissionError:
        print("Permission denied to access the log file.")
    except Exception as e:
        print(f"Error: {e}")

def application_management():
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("wmic product get name, version", shell=True, universal_newlines=True)
            print("\n********** Installed Applications **********")
            print(output)
        else:
            print("Application management is currently supported only on Windows.")
    except subprocess.CalledProcessError as e:
        print("Error:", e.output)

def user_management():
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("net user", shell=True, universal_newlines=True)
            print("\n********** User Accounts **********")
            print(output)
        else:
            print("User management is currently supported only on Windows.")
    except subprocess.CalledProcessError as e:
        print("Error:", e.output)

def file_search():
    try:
        search_path = input("Enter the directory path to search: ")
        search_text = input("Enter the text to search in files: ")
        for root, _, files in os.walk(search_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            if search_text in line:
                                print(f"Found in: {file_path}")
                                break
                except (UnicodeDecodeError, PermissionError):
                    continue
    except FileNotFoundError:
        print("Directory not found.")
    except Exception as e:
        print(f"Error: {e}")

def security_checks():
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("netsh advfirewall show allprofiles", shell=True, universal_newlines=True)
            print("\n********** Firewall Status **********")
            print(output)
            output = subprocess.check_output("powershell Get-MpComputerStatus", shell=True, universal_newlines=True)
            print("\n********** Anti-virus Status **********")
            print(output)
        else:
            print("Security checks are currently supported only on Windows.")
    except subprocess.CalledProcessError as e:
        print("Error:", e.output)

def performance_monitoring():
    clear_screen()
    print("\n********** Performance Monitoring **********")
    print("CPU Usage: {}%".format(psutil.cpu_percent(interval=1)))
    print("RAM Usage: {:.2f} GB".format(psutil.virtual_memory().used / (1024.0 ** 3)))
    partitions = psutil.disk_partitions()
    print("\n********** Disk Usage **********")
    for partition in partitions:
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
            print("{} - Total: {}, Used: {}, Free: {}, Percent: {}%".format(
                partition.device,
                convert_bytes(partition_usage.total),
                convert_bytes(partition_usage.used),
                convert_bytes(partition_usage.free),
                partition_usage.percent
            ))
        except PermissionError:
            continue

def task_scheduler_management():
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("schtasks /query /fo LIST", shell=True, universal_newlines=True)
            print("\n********** Task Scheduler **********")
            print(output)
        else:
            print("Task scheduler management is currently supported only on Windows.")
    except subprocess.CalledProcessError as e:
        print("Error:", e.output)

def printer_management():
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("wmic printer get name", shell=True, universal_newlines=True)
            print("\n********** Installed Printers **********")
            print(output)
        else:
            print("Printer management is currently supported only on Windows.")
    except subprocess.CalledProcessError as e:
        print("Error:", e.output)

def main():
    while True:
        main_menu()
        choice = input("\nEnter your choice (1-18): ")

        if choice == '1':
            while True:
                file_folder_operations_menu()
                choice2 = input("\nEnter your choice (1-7): ")

                if choice2 == '1':
                    create_file_folder()
                elif choice2 == '2':
                    delete_file_folder()
                elif choice2 == '3':
                    list_files_folders()
                elif choice2 == '4':
                    copy_file_folder()
                elif choice2 == '5':
                    move_file_folder()
                elif choice2 == '6':
                    rename_file_folder()
                elif choice2 == '7':
                    break
                else:
                    print("Invalid choice!")

        elif choice == '2':
            task_manager()
        elif choice == '3':
            system_information()
        elif choice == '4':
            disk_space_information()
        elif choice == '5':
            run_system_command()
        elif choice == '6':
            open_browser()
        elif choice == '7':
            weather()
        elif choice == '8':
            virtual_machine_management()
        elif choice == '9':
            network_information()
        elif choice == '10':
            system_logs()
        elif choice == '11':
            application_management()
        elif choice == '12':
            user_management()
        elif choice == '13':
            file_search()
        elif choice == '14':
            security_checks()
        elif choice == '15':
            performance_monitoring()
        elif choice == '16':
            task_scheduler_management()
        elif choice == '17':
            printer_management()
        elif choice == '18':
            print("Exiting...")
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()
