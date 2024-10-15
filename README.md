# Simple Windows System Management Tool Developed with Python


## Introduction

This project is a Python-based system management tool designed to facilitate various administrative tasks on the Windows operating system. The tool offers a user-friendly console interface, allowing users to perform operations related to file management, system information retrieval, network monitoring, and more.


## Features

1. File/Folder Operations:

- Create, delete, list, copy, move, and rename  files and folders.
- User input is utilized for specifying paths and file names.

2. Task Manager:

- Open the Windows Task Manager to manage running processes.

3. System Information:

- Display information about the operating system, version, architecture, and Python version.

4. Disk Space Information:

- Show disk partitions and their respective usage statistics, including total size, used space, free space, and usage percentage.

5. Run System Command:

- Execute arbitrary system commands and display the output.

6. Web Browser:

- Open a specified URL in the default web browser.
Weather Information:

- Fetch and display weather information for a specified city using web scraping techniques.

7. Network Information:

- List active network connections.

8. Application Management:

- Retrieve and display a list of installed applications on the system.

9. User Management:

- Display user accounts on the system.

10. File Search:

- Search for specific text within files in a specified directory.

11. Security Checks:

- Check firewall and antivirus statuses.

12. Performance Monitoring:

- Monitor CPU and RAM usage.

13. Task Scheduler Management:

- Display tasks scheduled in the Windows Task Scheduler.

14. Printer Management:

- List installed printers on the system.



  
## Technical Implementation

* Programming Language: Python
* Libraries Used:
* os and shutil for file and folder operations.
* psutil for system and performance monitoring.
* platform for system information.
* subprocess for executing system commands.
* webbrowser for opening URLs.
* requests and BeautifulSoup for web scraping (weather information).
* pyautogui for potential GUI automation tasks (not implemented in the current version).

## Other information

1. User Interface
- The tool features a console-based interface that allows users to navigate through various options easily. The menu system is clear and organized, enabling straightforward access to all functionalities.

2. Challenges Faced
- Ensuring compatibility across different versions of Windows.
- Handling exceptions and errors gracefully to avoid crashes.
- Implementing web scraping responsibly to fetch weather data.
3. Conclusion
- The Simple Windows System Management Tool serves as a comprehensive utility for managing and monitoring a Windows system effectively. Its modular design allows for easy extension and integration of additional features in future updates. The project demonstrates a solid understanding of Python programming and practical applications of system management.

4. Future Enhancements
- Implement a graphical user interface (GUI) for improved user experience.
- Add more advanced features such as remote system management and integration with cloud services.
- Enhance error handling and logging for better troubleshooting.
