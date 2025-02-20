import os
import shutil
import psutil
import platform
import subprocess
import webbrowser
import requests
from bs4 import BeautifulSoup
import pyautogui
import warnings
import time
import ctypes
import random
from PyQt5.QtCore import Qt, QTimer, QRect
from PyQt5.QtGui import QPainter, QColor, QFont

# 2
warnings.filterwarnings("ignore", category=DeprecationWarning)
# 1
warnings.filterwarnings("ignore", message="No libpcap provider available")
warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", category=UserWarning)

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QPushButton, QLabel, QFileDialog, QInputDialog, 
                            QMessageBox, QTabWidget, QGridLayout, QLineEdit,
                            QTextEdit, QProgressBar, QFrame, QScrollArea,
                            QGroupBox, QCheckBox, QHBoxLayout, QMenu, QComboBox)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor, QCursor
import sys
import socket
import nmap
import hashlib
import winreg
import win32security
import win32api
import win32con
import re
from datetime import datetime
from scapy.all import *
import win32net
import win32netcon
import win32security
import win32api
import win32con
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import json
import threading
import dns.resolver
import win32service
import win32serviceutil

class CustomButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setMinimumHeight(40)
        self.setCursor(Qt.PointingHandCursor)

class CustomTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QGridLayout()
        self.setLayout(self.layout)
        self.layout.setSpacing(10)
        self.layout.setContentsMargins(20, 20, 20, 20)

class UserManagementWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Kullanıcı Yönetimi")
        self.setGeometry(200, 200, 1000, 600)
        
        # Ana widget ve layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Sol taraf - Kullanıcı listesi
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setLayout(left_layout)
        
        list_label = QLabel("Mevcut Kullanıcılar:")
        list_label.setStyleSheet("font-size: 14px; font-weight: bold; margin-bottom: 10px;")
        left_layout.addWidget(list_label)
        
        self.user_list = QTextEdit()
        self.user_list.setReadOnly(True)
        self.user_list.setMinimumWidth(400)
        left_layout.addWidget(self.user_list)
        
        main_layout.addWidget(left_widget)
        
        # Sağ taraf - İşlem butonları
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_widget.setLayout(right_layout)
        right_widget.setMinimumWidth(300)
        
        # Kullanıcı Ekleme Bölümü
        add_group = QGroupBox("Kullanıcı Ekle")
        add_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #1976D2;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        add_layout = QVBoxLayout()
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Kullanıcı Adı")
        self.username_input.setMinimumHeight(30)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Şifre")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(30)
        
        self.admin_checkbox = QCheckBox("Admin Yetkisi Ver")
        self.admin_checkbox.setStyleSheet("margin-top: 5px;")
        
        add_user_btn = QPushButton("Kullanıcı Ekle")
        add_user_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        add_user_btn.clicked.connect(self.add_user)
        
        add_layout.addWidget(self.username_input)
        add_layout.addWidget(self.password_input)
        add_layout.addWidget(self.admin_checkbox)
        add_layout.addWidget(add_user_btn)
        add_group.setLayout(add_layout)
        
        # Kullanıcı Silme Bölümü
        delete_group = QGroupBox("Kullanıcı Sil")
        delete_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #f44336;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        delete_layout = QVBoxLayout()
        
        self.delete_username_input = QLineEdit()
        self.delete_username_input.setPlaceholderText("Silinecek Kullanıcı Adı")
        self.delete_username_input.setMinimumHeight(30)
        
        delete_user_btn = QPushButton("Kullanıcı Sil")
        delete_user_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
        """)
        delete_user_btn.clicked.connect(self.delete_user)
        
        delete_layout.addWidget(self.delete_username_input)
        delete_layout.addWidget(delete_user_btn)
        delete_group.setLayout(delete_layout)
        
        # Yetki Değiştirme Bölümü
        permission_group = QGroupBox("Yetki Değiştir")
        permission_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid #2196F3;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        permission_layout = QVBoxLayout()
        
        self.permission_username_input = QLineEdit()
        self.permission_username_input.setPlaceholderText("Kullanıcı Adı")
        self.permission_username_input.setMinimumHeight(30)
        
        self.permission_admin_checkbox = QCheckBox("Admin Yetkisi")
        self.permission_admin_checkbox.setStyleSheet("margin-top: 5px;")
        
        change_permission_btn = QPushButton("Yetkileri Değiştir")
        change_permission_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        change_permission_btn.clicked.connect(self.change_permissions)
        
        permission_layout.addWidget(self.permission_username_input)
        permission_layout.addWidget(self.permission_admin_checkbox)
        permission_layout.addWidget(change_permission_btn)
        permission_group.setLayout(permission_layout)
        
        # Sağ tarafa bölümleri ekle
        right_layout.addWidget(add_group)
        right_layout.addWidget(delete_group)
        right_layout.addWidget(permission_group)
        right_layout.addStretch()
        
        main_layout.addWidget(right_widget)
        
        # Kullanıcı listesini güncelle
        self.update_user_list()
    
    def update_user_list(self):
        try:
            resume = 0
            self.user_list.clear()
            while True:
                users, _, resume = win32net.NetUserEnum(None, 0, win32netcon.FILTER_NORMAL_ACCOUNT, resume)
                for user in users:
                    try:
                        # Kullanıcı bilgilerini al
                        user_info = win32net.NetUserGetInfo(None, user['name'], 1)
                        # Admin kontrolü
                        is_admin = self.is_user_admin(user['name'])
                        admin_text = "Admin" if is_admin else "Normal Kullanıcı"
                        
                        self.user_list.append(f"Kullanıcı Adı: {user['name']}")
                        self.user_list.append(f"Yetki: {admin_text}")
                        self.user_list.append(f"Açıklama: {user_info['comment']}")
                        self.user_list.append("-" * 40)
                    except win32net.error:
                        continue
                
                if not resume:
                    break
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Kullanıcı listesi alınırken hata oluştu: {str(e)}")
    
    def is_user_admin(self, username):
        try:
            # Administrators grubunun SID'sini al
            admin_sid = win32security.ConvertStringSidToSid("S-1-5-32-544")
            # Administrators grubunun üyelerini al
            members, _, _ = win32net.NetLocalGroupGetMembers(None, "Administrators", 1)
            # Kullanıcının admin grubunda olup olmadığını kontrol et
            return any(member['name'].lower() == username.lower() for member in members)
        except:
            return False
    
    def add_user(self):
        username = self.username_input.text()
        password = self.password_input.text()
        is_admin = self.admin_checkbox.isChecked()
        
        if not username or not password:
            QMessageBox.warning(self, "Hata", "Kullanıcı adı ve şifre gereklidir!")
            return
        
        try:
            # Kullanıcı bilgilerini hazırla
            user_info = {
                'name': username,
                'password': password,
                'priv': win32netcon.USER_PRIV_USER,
                'flags': win32netcon.UF_NORMAL_ACCOUNT | win32netcon.UF_SCRIPT,
            }
            
            # Kullanıcıyı oluştur
            win32net.NetUserAdd(None, 1, user_info)
            
            # Admin yetkisi verilecekse
            if is_admin:
                win32net.NetLocalGroupAddMembers(None, "Administrators", 3, [{'domainandname': username}])
            
            QMessageBox.information(self, "Başarılı", "Kullanıcı başarıyla oluşturuldu!")
            self.update_user_list()
            
            # Input alanlarını temizle
            self.username_input.clear()
            self.password_input.clear()
            self.admin_checkbox.setChecked(False)
            
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Kullanıcı oluşturulurken hata oluştu: {str(e)}")
    
    def delete_user(self):
        username = self.delete_username_input.text()
        
        if not username:
            QMessageBox.warning(self, "Hata", "Kullanıcı adı gereklidir!")
            return
        
        try:
            # Kullanıcıyı sil
            win32net.NetUserDel(None, username)
            
            QMessageBox.information(self, "Başarılı", "Kullanıcı başarıyla silindi!")
            self.update_user_list()
            
            # Input alanını temizle
            self.delete_username_input.clear()
            
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Kullanıcı silinirken hata oluştu: {str(e)}")
    
    def change_permissions(self):
        username = self.permission_username_input.text()
        should_be_admin = self.permission_admin_checkbox.isChecked()
        
        if not username:
            QMessageBox.warning(self, "Hata", "Kullanıcı adı gereklidir!")
            return
        
        try:
            if should_be_admin:
                # Admin grubuna ekle
                win32net.NetLocalGroupAddMembers(None, "Administrators", 3, [{'domainandname': username}])
            else:
                # Admin grubundan çıkar
                try:
                    win32net.NetLocalGroupDelMembers(None, "Administrators", [username])
                except:
                    pass
            
            QMessageBox.information(self, "Başarılı", "Kullanıcı yetkileri başarıyla güncellendi!")
            self.update_user_list()
            
            # Input alanlarını temizle
            self.permission_username_input.clear()
            self.permission_admin_checkbox.setChecked(False)
            
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Yetkiler değiştirilirken hata oluştu: {str(e)}")

class SystemInfoWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sistem Bilgileri")
        self.setGeometry(200, 200, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        self.info_viewer = QTextEdit()
        self.info_viewer.setReadOnly(True)
        layout.addWidget(self.info_viewer)
        
        self.show_system_info()
    
    def get_windows_product_key(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform", 
                                0, winreg.KEY_READ)
            backup_key_value = winreg.QueryValueEx(key, "BackupProductKeyDefault")[0]
            winreg.CloseKey(key)
            
            # Key türünü belirle
            key_type = "OEM Key"  # Varsayılan
            if len(backup_key_value) == 29:  # Retail key uzunluğu
                key_type = "Retail Key"
            elif "VOLUME_" in backup_key_value:
                key_type = "Volume License Key (VLK)"
            elif "MAK" in backup_key_value:
                key_type = "Multiple Activation Key (MAK)"
            
            return backup_key_value, key_type
        except:
            try:
                # Alternatif yöntem
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 
                                   0, winreg.KEY_READ)
                digital_id = winreg.QueryValueEx(key, "DigitalProductId")[0]
                winreg.CloseKey(key)
                return "Şifrelenmiş Product Key bulundu", "Digital License"
            except:
                return "Bulunamadı", "Bilinmiyor"
    
    def get_windows_license_type(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 
                                0, winreg.KEY_READ)
            edition_id = winreg.QueryValueEx(key, "EditionID")[0]
            winreg.CloseKey(key)
            
            # Detaylı lisans türü kontrolü
            if "Enterprise" in edition_id:
                if "LTSB" in edition_id or "LTSC" in edition_id:
                    return "Kurumsal Lisans (LTSC/LTSB)"
                return "Kurumsal Lisans (Enterprise)"
            elif "Professional" in edition_id:
                if "Workstation" in edition_id:
                    return "Profesyonel İş İstasyonu Lisansı"
                return "Profesyonel Lisans"
            elif "Education" in edition_id:
                if "Pro" in edition_id:
                    return "Eğitim Pro Lisansı"
                return "Eğitim Lisansı"
            elif "Home" in edition_id:
                if "Single" in edition_id:
                    return "Ev Tek Dil Lisansı"
                return "Ev Lisansı"
            elif "Core" in edition_id:
                if "N" in edition_id:
                    return "Windows 10/11 Core N Lisansı"
                return "Windows 10/11 Core Lisansı"
            else:
                return f"Diğer ({edition_id})"
        except:
            return "Bulunamadı"
    
    def show_system_info(self):
        try:
            self.info_viewer.clear()
            self.info_viewer.append("=== Sistem Bilgileri ===\n")
            
            # Windows Lisans Bilgileri
            self.info_viewer.append("=== Windows Lisans Bilgileri ===")
            self.info_viewer.append(f"Lisans Türü: {self.get_windows_license_type()}")
            key_value, key_type = self.get_windows_product_key()
            self.info_viewer.append(f"Product Key: {key_value}")
            self.info_viewer.append(f"Key Türü: {key_type}")
            self.info_viewer.append("")
            
            # Temel sistem bilgileri
            self.info_viewer.append("=== Temel Sistem Bilgileri ===")
            self.info_viewer.append(f"İşletim Sistemi: {platform.system()}")
            self.info_viewer.append(f"Sürüm: {platform.release()}")
            self.info_viewer.append(f"Architecture: {platform.machine()}")
            self.info_viewer.append(f"İşlemci: {platform.processor()}")
            self.info_viewer.append(f"Bilgisayar Adı: {platform.node()}")
            self.info_viewer.append(f"Python Version: {platform.python_version()}")
            
            # CPU Bilgileri
            cpu_info = psutil.cpu_freq()
            cpu_count = psutil.cpu_count()
            cpu_count_logical = psutil.cpu_count(logical=True)
            
            self.info_viewer.append("\n=== İşlemci Bilgileri ===")
            self.info_viewer.append(f"Fiziksel Çekirdek Sayısı: {cpu_count}")
            self.info_viewer.append(f"Mantıksal Çekirdek Sayısı: {cpu_count_logical}")
            if cpu_info:
                self.info_viewer.append(f"CPU Frekansı: {cpu_info.current:.2f} MHz")
                self.info_viewer.append(f"Minimum Frekans: {cpu_info.min:.2f} MHz")
                self.info_viewer.append(f"Maksimum Frekans: {cpu_info.max:.2f} MHz")
            
            # CPU Kullanımı
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            self.info_viewer.append("\nCPU Kullanımı (Çekirdek Bazlı):")
            for i, percent in enumerate(cpu_percent):
                self.info_viewer.append(f"Çekirdek {i}: %{percent}")
            
            # Bellek (RAM) Bilgileri
            memory = psutil.virtual_memory()
            self.info_viewer.append("\n=== RAM Bilgileri ===")
            self.info_viewer.append(f"Toplam RAM: {format_bytes(memory.total)}")
            self.info_viewer.append(f"Kullanılan RAM: {format_bytes(memory.used)}")
            self.info_viewer.append(f"Boş RAM: {format_bytes(memory.available)}")
            self.info_viewer.append(f"RAM Kullanım Yüzdesi: %{memory.percent}")
            
            # Disk Bilgileri
            self.info_viewer.append("\n=== Disk Bilgileri ===")
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    self.info_viewer.append(f"\nSürücü: {partition.device}")
                    self.info_viewer.append(f"Bağlantı Noktası: {partition.mountpoint}")
                    self.info_viewer.append(f"Dosya Sistemi: {partition.fstype}")
                    self.info_viewer.append(f"Toplam Alan: {format_bytes(usage.total)}")
                    self.info_viewer.append(f"Kullanılan Alan: {format_bytes(usage.used)}")
                    self.info_viewer.append(f"Boş Alan: {format_bytes(usage.free)}")
                    self.info_viewer.append(f"Kullanım Yüzdesi: %{usage.percent}")
                except:
                    continue
            
            # Ağ Bilgileri
            self.info_viewer.append("\n=== Ağ Adaptörleri ===")
            for interface_name, interface_addresses in psutil.net_if_addrs().items():
                self.info_viewer.append(f"\nArayüz: {interface_name}")
                for addr in interface_addresses:
                    if addr.family == socket.AF_INET:
                        self.info_viewer.append(f"  IPv4 Adresi: {addr.address}")
                        self.info_viewer.append(f"  Ağ Maskesi: {addr.netmask}")
                    elif addr.family == socket.AF_INET6:
                        self.info_viewer.append(f"  IPv6 Adresi: {addr.address}")
            
            # Ağ İstatistikleri
            net_io = psutil.net_io_counters()
            self.info_viewer.append("\n=== Ağ İstatistikleri ===")
            self.info_viewer.append(f"Gönderilen Veri: {format_bytes(net_io.bytes_sent)}")
            self.info_viewer.append(f"Alınan Veri: {format_bytes(net_io.bytes_recv)}")
            self.info_viewer.append(f"Gönderilen Paket: {net_io.packets_sent}")
            self.info_viewer.append(f"Alınan Paket: {net_io.packets_recv}")
            
            # Çalışan Süreç Bilgileri
            self.info_viewer.append("\n=== Çalışan Süreç Bilgileri ===")
            process_count = len(psutil.pids())
            self.info_viewer.append(f"Toplam Çalışan Süreç Sayısı: {process_count}")
            
            # Sistem Çalışma Süresi
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            self.info_viewer.append("\n=== Sistem Çalışma Süresi ===")
            self.info_viewer.append(f"Başlangıç Zamanı: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}")
            self.info_viewer.append(f"Çalışma Süresi: {uptime}")
            
            # Batarya Bilgileri (varsa)
            if hasattr(psutil, 'sensors_battery') and psutil.sensors_battery():
                battery = psutil.sensors_battery()
                self.info_viewer.append("\n=== Batarya Bilgileri ===")
                self.info_viewer.append(f"Şarj Yüzdesi: %{battery.percent}")
                self.info_viewer.append(f"Şarj Oluyor: {'Evet' if battery.power_plugged else 'Hayır'}")
                if battery.secsleft != psutil.POWER_TIME_UNLIMITED:
                    minutes = battery.secsleft // 60
                    self.info_viewer.append(f"Kalan Süre: {minutes} dakika")
            
            # Sıcaklık Sensörleri (varsa)
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                if temps:
                    self.info_viewer.append("\n=== Sıcaklık Bilgileri ===")
                    for name, entries in temps.items():
                        for entry in entries:
                            self.info_viewer.append(f"{name}: {entry.current}°C")
            
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Sistem bilgileri alınırken hata oluştu: {str(e)}")

    def format_bytes(self, bytes):
        """Byte değerini okunaklı formata çevirir"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} PB"

class PerformanceWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Performans İzleme")
        self.setGeometry(200, 200, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Güncelleme aralığı kontrolü
        update_layout = QHBoxLayout()
        self.update_interval = QLineEdit()
        self.update_interval.setPlaceholderText("Güncelleme aralığı (saniye)")
        self.update_interval.setText("3")
        update_btn = QPushButton("Aralığı Güncelle")
        update_btn.clicked.connect(self.change_update_interval)
        update_layout.addWidget(self.update_interval)
        update_layout.addWidget(update_btn)
        layout.addLayout(update_layout)
        
        self.perf_viewer = QTextEdit()
        self.perf_viewer.setReadOnly(True)
        layout.addWidget(self.perf_viewer)
        
        # Otomatik güncelleme için timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_performance)
        self.timer.start(3000)  # 3 saniyede bir güncelle
        
        # Önbellek için değişkenler
        self.last_process_check = 0
        self.process_cache = []
        self.process_check_interval = 5  # 5 saniyede bir süreç listesini güncelle
        
        self.update_performance()
    
    def change_update_interval(self):
        try:
            interval = int(self.update_interval.text())
            if interval < 1:
                raise ValueError("Aralık 1 saniyeden küçük olamaz")
            self.timer.setInterval(interval * 1000)
            QMessageBox.information(self, "Başarılı", f"Güncelleme aralığı {interval} saniye olarak ayarlandı")
        except ValueError as e:
            QMessageBox.warning(self, "Hata", str(e))
    
    def update_performance(self):
        try:
            self.perf_viewer.clear()
            self.perf_viewer.append("=== Performans İzleme ===\n")
            
            # CPU Kullanımı
            cpu_percent = psutil.cpu_percent(interval=None)
            self.perf_viewer.append(f"Toplam CPU Kullanımı: %{cpu_percent}")
            
            # RAM Kullanımı
            memory = psutil.virtual_memory()
            self.perf_viewer.append(f"\nRAM Kullanımı: %{memory.percent}")
            self.perf_viewer.append(f"Kullanılan RAM: {format_bytes(memory.used)}")
            self.perf_viewer.append(f"Boş RAM: {format_bytes(memory.available)}")
            
            # Disk Kullanımı
            self.perf_viewer.append("\nDisk Kullanımı:")
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    if usage.total > 0:  # Sadece gerçek diskleri göster
                        self.perf_viewer.append(f"\nSürücü: {partition.device}")
                        self.perf_viewer.append(f"Kullanım: %{usage.percent}")
                except:
                    continue
            
            # Süreç listesini belirli aralıklarla güncelle
            current_time = time.time()
            if current_time - self.last_process_check >= self.process_check_interval:
                self.process_cache = []
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        pinfo = proc.info
                        if pinfo['cpu_percent'] > 0.5:  # Sadece CPU kullanan süreçleri göster
                            processes.append(pinfo)
                    except:
                        continue
                
                # CPU kullanımına göre sırala
                processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
                self.process_cache = processes[:5]  # İlk 5 süreci önbellekle
                self.last_process_check = current_time
            
            # Önbelleklenmiş süreç listesini göster
            if self.process_cache:
                self.perf_viewer.append("\nEn Çok Kaynak Kullanan Süreçler:")
                for proc in self.process_cache:
                    self.perf_viewer.append(f"\nPID: {proc['pid']}")
                    self.perf_viewer.append(f"Ad: {proc['name']}")
                    self.perf_viewer.append(f"CPU: %{proc['cpu_percent']:.1f}")
                    self.perf_viewer.append(f"RAM: %{proc['memory_percent']:.1f}")
            
        except Exception as e:
            self.perf_viewer.append(f"\nHata: {str(e)}")

    def format_bytes(self, bytes):
        """Byte değerini okunaklı formata çevirir"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} PB"

class SecurityWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Şifre Güvenliği Kontrolü")
        self.setGeometry(200, 200, 600, 400)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Şifre girişi
        input_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Şifre girin")
        check_btn = QPushButton("Kontrol Et")
        check_btn.clicked.connect(self.check_password)
        input_layout.addWidget(self.password_input)
        input_layout.addWidget(check_btn)
        layout.addLayout(input_layout)
        
        # Sonuç gösterimi
        self.result_viewer = QTextEdit()
        self.result_viewer.setReadOnly(True)
        layout.addWidget(self.result_viewer)
    
    def check_password(self):
        password = self.password_input.text()
        if password:
            score = 0
            feedback = []
            
            if len(password) >= 8:
                score += 1
                feedback.append("✓ Şifre uzunluğu yeterli")
            else:
                feedback.append("✗ Şifre en az 8 karakter olmalı")
            
            if re.search(r"[A-Z]", password):
                score += 1
                feedback.append("✓ Büyük harf var")
            else:
                feedback.append("✗ Büyük harf eksik")
            
            if re.search(r"[a-z]", password):
                score += 1
                feedback.append("✓ Küçük harf var")
            else:
                feedback.append("✗ Küçük harf eksik")
            
            if re.search(r"\d", password):
                score += 1
                feedback.append("✓ Rakam var")
            else:
                feedback.append("✗ Rakam eksik")
            
            if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
                score += 1
                feedback.append("✓ Özel karakter var")
            else:
                feedback.append("✗ Özel karakter eksik")
            
            self.result_viewer.clear()
            self.result_viewer.append("Şifre Güvenlik Analizi:\n")
            self.result_viewer.append(f"Güvenlik Puanı: {score}/5\n")
            self.result_viewer.append("\n".join(feedback))

class NetworkAnalyzerWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ağ Trafiği Analizi")
        self.setGeometry(200, 200, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Kontrol butonları
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("Yenile")
        refresh_btn.clicked.connect(self.analyze_network)
        btn_layout.addWidget(refresh_btn)
        layout.addLayout(btn_layout)
        
        # Analiz sonuçları
        self.network_viewer = QTextEdit()
        self.network_viewer.setReadOnly(True)
        layout.addWidget(self.network_viewer)
        
        self.analyze_network()
    
    def analyze_network(self):
        try:
            self.network_viewer.clear()
            self.network_viewer.append("Ağ Trafiği Analizi Başlatıldı...\n")
            
            # Aktif bağlantıları kontrol et
            self.network_viewer.append("=== Aktif Bağlantılar ===\n")
            try:
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    self.network_viewer.append(f"Yerel: {local_addr} -> Uzak: {remote_addr} [Durum: {conn.status}]")
            except Exception as e:
                self.network_viewer.append(f"Bağlantı bilgileri alınamadı: {str(e)}\n")
            
            # Ağ adaptörlerini listele
            self.network_viewer.append("\n=== Ağ Adaptörleri ===\n")
            try:
                for interface_name, interface_addresses in psutil.net_if_addrs().items():
                    self.network_viewer.append(f"\nArayüz: {interface_name}")
                    for addr in interface_addresses:
                        if addr.family == socket.AF_INET:
                            self.network_viewer.append(f"  IPv4 Adresi: {addr.address}")
                            self.network_viewer.append(f"  Ağ Maskesi: {addr.netmask}")
                        elif addr.family == socket.AF_INET6:
                            self.network_viewer.append(f"  IPv6 Adresi: {addr.address}")
                
                # Ağ arayüz durumları
                net_if_stats = psutil.net_if_stats()
                for interface_name, stats in net_if_stats.items():
                    self.network_viewer.append(f"\nArayüz Durumu: {interface_name}")
                    self.network_viewer.append(f"  Aktif: {'Evet' if stats.isup else 'Hayır'}")
                    self.network_viewer.append(f"  Hız: {stats.speed} Mbps")
                    self.network_viewer.append(f"  MTU: {stats.mtu}")
            except Exception as e:
                self.network_viewer.append(f"Ağ adaptör bilgileri alınamadı: {str(e)}\n")
            
            # Ağ istatistiklerini al
            self.network_viewer.append("\n=== Ağ İstatistikleri ===\n")
            try:
                stats = psutil.net_io_counters(pernic=True)
                for interface, stat in stats.items():
                    self.network_viewer.append(f"\nArayüz: {interface}")
                    self.network_viewer.append(f"  Gönderilen: {format_bytes(stat.bytes_sent)}")
                    self.network_viewer.append(f"  Alınan: {format_bytes(stat.bytes_recv)}")
                    self.network_viewer.append(f"  Gönderilen Paket: {stat.packets_sent}")
                    self.network_viewer.append(f"  Alınan Paket: {stat.packets_recv}")
                    self.network_viewer.append(f"  Hata (Gönderme): {stat.errin}")
                    self.network_viewer.append(f"  Hata (Alma): {stat.errout}")
                    self.network_viewer.append(f"  Drop (Gönderme): {stat.dropin}")
                    self.network_viewer.append(f"  Drop (Alma): {stat.dropout}")
            except Exception as e:
                self.network_viewer.append(f"Ağ istatistikleri alınamadı: {str(e)}\n")
            
            # Genel ağ performans bilgileri
            self.network_viewer.append("\n=== Ağ Performans Özeti ===\n")
            try:
                total_stats = psutil.net_io_counters()
                self.network_viewer.append(f"Toplam Gönderilen: {format_bytes(total_stats.bytes_sent)}")
                self.network_viewer.append(f"Toplam Alınan: {format_bytes(total_stats.bytes_recv)}")
                self.network_viewer.append(f"Toplam Gönderilen Paket: {total_stats.packets_sent}")
                self.network_viewer.append(f"Toplam Alınan Paket: {total_stats.packets_recv}")
                self.network_viewer.append(f"Toplam Hata (Gönderme): {total_stats.errin}")
                self.network_viewer.append(f"Toplam Hata (Alma): {total_stats.errout}")
                self.network_viewer.append(f"Toplam Drop (Gönderme): {total_stats.dropin}")
                self.network_viewer.append(f"Toplam Drop (Alma): {total_stats.dropout}")
            except Exception as e:
                self.network_viewer.append(f"Ağ performans bilgileri alınamadı: {str(e)}\n")
            
            # Açık portları kontrol et
            self.network_viewer.append("\n=== Açık Portlar ===\n")
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'LISTEN':
                        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                        self.network_viewer.append(f"Dinlenen Port: {local_addr}")
            except Exception as e:
                self.network_viewer.append(f"Port bilgileri alınamadı: {str(e)}\n")
            
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Ağ trafiği analizi hatası: {str(e)}")
            
        finally:
            self.network_viewer.append("\nAnaliz tamamlandı.")

    def format_bytes(self, bytes):
        """Byte değerini okunaklı formata çevirir"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes < 1024:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024
        return f"{bytes:.2f} PB"

class ARPCheckerWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ARP Zehirlenmesi Kontrolü")
        self.setGeometry(200, 200, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Kontrol butonu
        check_btn = QPushButton("Kontrol Et")
        check_btn.clicked.connect(self.check_arp)
        layout.addWidget(check_btn)
        
        # Sonuç gösterimi
        self.arp_viewer = QTextEdit()
        self.arp_viewer.setReadOnly(True)
        layout.addWidget(self.arp_viewer)
        
        self.check_arp()
    
    def check_arp(self):
        try:
            self.arp_viewer.clear()
            self.arp_viewer.append("ARP Zehirlenmesi Kontrolü Başlatıldı...\n")
            
            # Ağ arayüzlerini al
            interfaces = psutil.net_if_addrs()
            
            # Her arayüz için IP ve MAC adreslerini kontrol et
            suspicious_entries = []
            mac_count = {}
            
            for interface, addrs in interfaces.items():
                self.arp_viewer.append(f"\nArayüz: {interface}")
                
                # IP ve MAC adreslerini bul
                ipv4_addr = None
                mac_addr = None
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        ipv4_addr = addr.address
                    elif addr.family == psutil.AF_LINK:  # MAC
                        mac_addr = addr.address
                
                if ipv4_addr and mac_addr:
                    self.arp_viewer.append(f"IP Adresi: {ipv4_addr}")
                    self.arp_viewer.append(f"MAC Adresi: {mac_addr}")
                    
                    # MAC adresi sayısını kontrol et
                    mac_count[mac_addr] = mac_count.get(mac_addr, 0) + 1
                    if mac_count[mac_addr] > 1:
                        suspicious_entries.append((interface, ipv4_addr, mac_addr))
            
            # Şüpheli girişleri raporla
            if suspicious_entries:
                self.arp_viewer.append("\n⚠️ Şüpheli ARP Girişleri Tespit Edildi:")
                for entry in suspicious_entries:
                    self.arp_viewer.append(f"Arayüz: {entry[0]}")
                    self.arp_viewer.append(f"IP: {entry[1]}")
                    self.arp_viewer.append(f"MAC: {entry[2]}")
            else:
                self.arp_viewer.append("\n✅ Şüpheli ARP girişi tespit edilmedi.")
            
            # Ağ istatistiklerini kontrol et
            self.arp_viewer.append("\n=== Ağ İstatistikleri ===")
            try:
                stats = psutil.net_io_counters()
                self.arp_viewer.append(f"Toplam Paket Hatası: {stats.errin + stats.errout}")
                self.arp_viewer.append(f"Düşen Paket Sayısı: {stats.dropin + stats.dropout}")
                
                if (stats.errin + stats.errout) > 1000 or (stats.dropin + stats.dropout) > 1000:
                    self.arp_viewer.append("\n⚠️ Yüksek sayıda hatalı/düşen paket tespit edildi.")
                    self.arp_viewer.append("Bu durum bir ARP saldırısının göstergesi olabilir.")
            except Exception as e:
                self.arp_viewer.append(f"Ağ istatistikleri alınamadı: {str(e)}")
            
            # Bağlantı durumunu kontrol et
            self.arp_viewer.append("\n=== Bağlantı Durumu ===")
            try:
                connections = psutil.net_connections()
                suspicious_conns = []
                
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        suspicious_conns.append(conn)
                
                if len(suspicious_conns) > 50:  # Çok sayıda eşzamanlı bağlantı
                    self.arp_viewer.append("⚠️ Yüksek sayıda eşzamanlı bağlantı tespit edildi.")
                    self.arp_viewer.append("Bu durum bir ARP saldırısının göstergesi olabilir.")
                
                self.arp_viewer.append(f"Aktif Bağlantı Sayısı: {len(suspicious_conns)}")
            except Exception as e:
                self.arp_viewer.append(f"Bağlantı durumu alınamadı: {str(e)}")
            
            self.arp_viewer.append("\nKontrol tamamlandı.")
            
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"ARP kontrolü hatası: {str(e)}")

class DNSSecurityWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("DNS Güvenlik Kontrolü")
        self.setGeometry(200, 200, 1000, 800)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # DNS Sunucu Ayarları
        dns_group = QGroupBox("DNS Sunucu Ayarları")
        dns_layout = QVBoxLayout()
        
        # DNS Sunucu Seçimi
        dns_input_layout = QHBoxLayout()
        self.dns_input = QLineEdit()
        self.dns_input.setPlaceholderText("DNS Sunucusu (örn: 8.8.8.8)")
        self.dns_input.setMinimumWidth(200)
        
        dns_presets = QPushButton("Hazır DNS'ler")
        dns_presets.clicked.connect(self.show_dns_presets)
        
        dns_apply = QPushButton("Uygula")
        dns_apply.clicked.connect(self.change_dns)
        
        dns_input_layout.addWidget(self.dns_input)
        dns_input_layout.addWidget(dns_presets)
        dns_input_layout.addWidget(dns_apply)
        dns_layout.addLayout(dns_input_layout)
        
        # Mevcut DNS Gösterimi
        self.current_dns_label = QLabel()
        self.update_current_dns()
        dns_layout.addWidget(self.current_dns_label)
        
        dns_group.setLayout(dns_layout)
        layout.addWidget(dns_group)
        
        # Kontrol Butonları
        buttons_layout = QHBoxLayout()
        
        check_all_btn = QPushButton("Tüm Kontrolleri Yap")
        check_all_btn.clicked.connect(self.check_all)
        buttons_layout.addWidget(check_all_btn)
        
        leak_test_btn = QPushButton("DNS Sızıntı Testi")
        leak_test_btn.clicked.connect(self.check_dns_leak)
        buttons_layout.addWidget(leak_test_btn)
        
        security_rating_btn = QPushButton("Güvenlik Derecelendirmesi")
        security_rating_btn.clicked.connect(self.check_security_rating)
        buttons_layout.addWidget(security_rating_btn)
        
        records_btn = QPushButton("DNS Kayıtları Kontrolü")
        records_btn.clicked.connect(self.check_dns_records)
        buttons_layout.addWidget(records_btn)
        
        dnssec_btn = QPushButton("DNSSEC Kontrolü")
        dnssec_btn.clicked.connect(self.check_dnssec)
        buttons_layout.addWidget(dnssec_btn)
        
        clear_cache_btn = QPushButton("Önbellek Temizle")
        clear_cache_btn.clicked.connect(self.clear_dns_cache)
        buttons_layout.addWidget(clear_cache_btn)
        
        encryption_btn = QPushButton("Şifreleme Kontrolü")
        encryption_btn.clicked.connect(self.check_encryption)
        buttons_layout.addWidget(encryption_btn)
        
        layout.addLayout(buttons_layout)
        
        # Sonuç gösterimi
        self.dns_viewer = QTextEdit()
        self.dns_viewer.setReadOnly(True)
        layout.addWidget(self.dns_viewer)
    
    def update_current_dns(self):
        try:
            resolver = dns.resolver.Resolver()
            nameservers = resolver.nameservers
            self.current_dns_label.setText(f"Mevcut DNS Sunucuları: {', '.join(nameservers)}")
        except:
            self.current_dns_label.setText("DNS sunucuları alınamadı!")
    
    def show_dns_presets(self):
        presets = {
            "Google DNS": ["8.8.8.8", "8.8.4.4"],
            "Cloudflare DNS": ["1.1.1.1", "1.0.0.1"],
            "OpenDNS": ["208.67.222.222", "208.67.220.220"],
            "Quad9": ["9.9.9.9", "149.112.112.112"],
            "AdGuard DNS": ["94.140.14.14", "94.140.15.15"]
        }
        
        menu = QMenu(self)
        for name, servers in presets.items():
            action = menu.addAction(f"{name} ({', '.join(servers)})")
            action.triggered.connect(lambda checked, s=servers[0]: self.dns_input.setText(s))
        
        menu.exec_(QCursor.pos())
    
    def change_dns(self):
        dns_server = self.dns_input.text().strip()
        if not dns_server:
            QMessageBox.warning(self, "Hata", "DNS sunucusu giriniz!")
            return
        
        try:
            # Windows'ta DNS değiştirme komutu
            subprocess.run(['netsh', 'interface', 'ip', 'set', 'dns', 'name="Ethernet"', f'static {dns_server}'], check=True)
            QMessageBox.information(self, "Başarılı", "DNS sunucusu değiştirildi!")
            self.update_current_dns()
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"DNS değiştirilemedi: {str(e)}")
    
    def check_all(self):
        self.dns_viewer.clear()
        self.dns_viewer.append("=== Kapsamlı DNS Güvenlik Kontrolü ===\n")
        
        self.check_dns_leak()
        self.check_security_rating()
        self.check_dns_records()
        self.check_dnssec()
        self.check_encryption()
    
    def check_dns_leak(self):
        self.dns_viewer.append("\n=== DNS Sızıntı Testi ===")
        try:
            # DNS sızıntı testi için popüler domainleri kontrol et
            test_domains = ['whoami.akamai.net', 'resolver.dnscrypt.info']
            resolvers_found = set()
            
            for domain in test_domains:
                try:
                    answers = dns.resolver.resolve(domain, 'A')
                    for rdata in answers:
                        resolvers_found.add(str(rdata))
                except:
                    continue
            
            if len(resolvers_found) > 1:
                self.dns_viewer.append("⚠️ DNS Sızıntısı Tespit Edildi!")
                self.dns_viewer.append("Birden fazla DNS çözümleyici kullanılıyor:")
                for resolver in resolvers_found:
                    self.dns_viewer.append(f"• {resolver}")
            else:
                self.dns_viewer.append("✅ DNS Sızıntısı Tespit Edilmedi")
        except Exception as e:
            self.dns_viewer.append(f"❌ Test sırasında hata: {str(e)}")
    
    def check_security_rating(self):
        self.dns_viewer.append("\n=== DNS Sunucu Güvenlik Derecelendirmesi ===")
        try:
            resolver = dns.resolver.Resolver()
            nameservers = resolver.nameservers
            
            for ns in nameservers:
                score = 0
                feedback = []
                
                # DNSSEC desteği
                try:
                    dns.resolver.resolve('dnssec-deployment.org', 'A')
                    score += 2
                    feedback.append("✓ DNSSEC destekleniyor")
                except:
                    feedback.append("✗ DNSSEC desteklenmiyor")
                
                # DNS over TLS/HTTPS desteği
                try:
                    socket.create_connection((ns, 853), timeout=2)
                    score += 2
                    feedback.append("✓ DNS over TLS destekleniyor")
                except:
                    feedback.append("✗ DNS over TLS desteklenmiyor")
                
                # Yanıt süresi
                try:
                    start_time = time.time()
                    socket.gethostbyname('google.com')
                    response_time = (time.time() - start_time) * 1000
                    if response_time < 50:
                        score += 2
                        feedback.append("✓ Hızlı yanıt süresi")
                    else:
                        score += 1
                        feedback.append("△ Ortalama yanıt süresi")
                except:
                    feedback.append("✗ Yanıt süresi test edilemedi")
                
                self.dns_viewer.append(f"\nDNS Sunucu: {ns}")
                self.dns_viewer.append(f"Güvenlik Puanı: {score}/6")
                self.dns_viewer.append("\n".join(feedback))
        except Exception as e:
            self.dns_viewer.append(f"❌ Derecelendirme hatası: {str(e)}")
    
    def check_dns_records(self):
        self.dns_viewer.append("\n=== DNS Kayıtları Kontrolü ===")
        try:
            test_domain = 'google.com'
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(test_domain, record_type)
                    self.dns_viewer.append(f"\n{record_type} Kayıtları:")
                    for rdata in answers:
                        self.dns_viewer.append(f"• {str(rdata)}")
                except Exception as e:
                    self.dns_viewer.append(f"❌ {record_type} kaydı alınamadı: {str(e)}")
        except Exception as e:
            self.dns_viewer.append(f"❌ Kayıt kontrolü hatası: {str(e)}")
    
    def check_dnssec(self):
        self.dns_viewer.append("\n=== DNSSEC Kontrolü ===")
        try:
            test_domains = ['dnssec-deployment.org', 'google.com', 'cloudflare.com']
            
            for domain in test_domains:
                try:
                    answers = dns.resolver.resolve(domain, 'DNSKEY')
                    self.dns_viewer.append(f"\n✅ {domain}: DNSSEC aktif")
                    self.dns_viewer.append(f"Anahtar sayısı: {len(answers)}")
                except dns.resolver.NoAnswer:
                    self.dns_viewer.append(f"⚠️ {domain}: DNSSEC anahtarı bulunamadı")
                except Exception as e:
                    self.dns_viewer.append(f"❌ {domain}: DNSSEC kontrolü başarısız: {str(e)}")
        except Exception as e:
            self.dns_viewer.append(f"❌ DNSSEC kontrolü hatası: {str(e)}")
    
    def clear_dns_cache(self):
        try:
            # Windows DNS önbelleğini temizle
            subprocess.run(['ipconfig', '/flushdns'], check=True)
            self.dns_viewer.append("\n✅ DNS önbelleği başarıyla temizlendi")
        except Exception as e:
            self.dns_viewer.append(f"\n❌ DNS önbelleği temizleme hatası: {str(e)}")
    
    def check_encryption(self):
        self.dns_viewer.append("\n=== DNS Şifreleme Durumu ===")
        try:
            resolver = dns.resolver.Resolver()
            nameservers = resolver.nameservers
            
            for ns in nameservers:
                self.dns_viewer.append(f"\nDNS Sunucu: {ns}")
                
                # DNS over TLS kontrolü
                try:
                    socket.create_connection((ns, 853), timeout=2)
                    self.dns_viewer.append("✓ DNS over TLS (DoT) destekleniyor")
                except:
                    self.dns_viewer.append("✗ DNS over TLS (DoT) desteklenmiyor")
                
                # DNS over HTTPS kontrolü
                try:
                    response = requests.get(f"https://{ns}/dns-query", timeout=2)
                    if response.status_code == 200:
                        self.dns_viewer.append("✓ DNS over HTTPS (DoH) destekleniyor")
                    else:
                        self.dns_viewer.append("✗ DNS over HTTPS (DoH) desteklenmiyor")
                except:
                    self.dns_viewer.append("✗ DNS over HTTPS (DoH) desteklenmiyor")
                
                # Şifreleme önerileri
                self.dns_viewer.append("\nŞifreleme Önerileri:")
                self.dns_viewer.append("1. DNS over HTTPS (DoH) kullanın")
                self.dns_viewer.append("2. DNS over TLS (DoT) kullanın")
                self.dns_viewer.append("3. Güvenilir DNS sağlayıcıları tercih edin")
        except Exception as e:
            self.dns_viewer.append(f"❌ Şifreleme kontrolü hatası: {str(e)}")

class PortScannerWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Port Tarama")
        self.setGeometry(200, 200, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Hedef IP girişi
        input_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Hedef IP adresi")
        scan_btn = QPushButton("Tara")
        scan_btn.clicked.connect(self.scan_ports)
        input_layout.addWidget(self.target_input)
        input_layout.addWidget(scan_btn)
        layout.addLayout(input_layout)
        
        # Sonuç gösterimi
        self.scan_viewer = QTextEdit()
        self.scan_viewer.setReadOnly(True)
        layout.addWidget(self.scan_viewer)
    
    def scan_ports(self):
        target = self.target_input.text()
        if target:
            try:
                self.scan_viewer.clear()
                self.scan_viewer.append(f"Port taraması başlatıldı: {target}\n")
                
                nm = nmap.PortScanner()
                nm.scan(target, '1-1024')
                
                for host in nm.all_hosts():
                    self.scan_viewer.append(f"\nHost : {host}")
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            state = nm[host][proto][port]['state']
                            self.scan_viewer.append(f"Port : {port}\tDurum : {state}")
            except Exception as e:
                QMessageBox.warning(self, "Hata", f"Port tarama hatası: {str(e)}")

class ServiceManagementWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Servis Yönetimi")
        self.setGeometry(200, 200, 1000, 600)
        
        # Yönetici izni kontrolü
        if not self.is_admin():
            QMessageBox.warning(self, "Yönetici İzni Gerekli", 
                "Servis yönetimi için programın yönetici olarak çalıştırılması gerekiyor.\n"
                "Lütfen programı kapatıp yönetici olarak yeniden çalıştırın.")
            self.close()
            return
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QHBoxLayout()
        central_widget.setLayout(layout)
        
        # Sol taraf - Servis listesi
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setLayout(left_layout)
        
        # Arama kutusu
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Servis ara...")
        self.search_input.textChanged.connect(self.filter_services)
        search_layout.addWidget(self.search_input)
        left_layout.addLayout(search_layout)
        
        # Servis listesi
        self.service_list = QTextEdit()
        self.service_list.setReadOnly(True)
        self.service_list.setMinimumWidth(400)
        left_layout.addWidget(self.service_list)
        
        layout.addWidget(left_widget)
        
        # Sağ taraf - Kontroller
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_widget.setLayout(right_layout)
        
        # Servis kontrolü
        control_group = QGroupBox("Servis Kontrolü")
        control_layout = QVBoxLayout()
        
        self.service_name_input = QLineEdit()
        self.service_name_input.setPlaceholderText("Servis adı")
        control_layout.addWidget(self.service_name_input)
        
        btn_start = QPushButton("Servisi Başlat")
        btn_start.clicked.connect(self.start_service)
        control_layout.addWidget(btn_start)
        
        btn_stop = QPushButton("Servisi Durdur")
        btn_stop.clicked.connect(self.stop_service)
        control_layout.addWidget(btn_stop)
        
        btn_restart = QPushButton("Servisi Yeniden Başlat")
        btn_restart.clicked.connect(self.restart_service)
        control_layout.addWidget(btn_restart)
        
        # Başlangıç türü
        startup_group = QHBoxLayout()
        startup_label = QLabel("Başlangıç Türü:")
        self.startup_combo = QComboBox()
        self.startup_combo.addItems(["Otomatik", "Manuel", "Devre Dışı"])
        btn_change_startup = QPushButton("Uygula")
        btn_change_startup.clicked.connect(self.change_startup_type)
        
        startup_group.addWidget(startup_label)
        startup_group.addWidget(self.startup_combo)
        startup_group.addWidget(btn_change_startup)
        control_layout.addLayout(startup_group)
        
        control_group.setLayout(control_layout)
        right_layout.addWidget(control_group)
        
        # Yenile butonu
        btn_refresh = QPushButton("Servisleri Yenile")
        btn_refresh.clicked.connect(self.refresh_services)
        right_layout.addWidget(btn_refresh)
        
        right_layout.addStretch()
        layout.addWidget(right_widget)
        
        # Servisleri listele
        self.refresh_services()
    
    def refresh_services(self):
        try:
            self.service_list.clear()
            services = win32service.EnumServicesStatus(
                win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            )
            
            for service in services:
                name = service[0]
                display_name = service[1]
                status = service[2]
                
                status_text = "Çalışıyor" if status[1] == win32service.SERVICE_RUNNING else "Durdu"
                
                self.service_list.append(f"Servis: {display_name}")
                self.service_list.append(f"Sistem Adı: {name}")
                self.service_list.append(f"Durum: {status_text}")
                self.service_list.append("-" * 50)
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Servisler listelenirken hata oluştu: {str(e)}")
    
    def filter_services(self):
        search_text = self.search_input.text().lower()
        try:
            self.service_list.clear()
            services = win32service.EnumServicesStatus(
                win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            )
            
            for service in services:
                name = service[0]
                display_name = service[1]
                status = service[2]
                
                if search_text in name.lower() or search_text in display_name.lower():
                    status_text = "Çalışıyor" if status[1] == win32service.SERVICE_RUNNING else "Durdu"
                    
                    self.service_list.append(f"Servis: {display_name}")
                    self.service_list.append(f"Sistem Adı: {name}")
                    self.service_list.append(f"Durum: {status_text}")
                    self.service_list.append("-" * 50)
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Servisler filtrelenirken hata oluştu: {str(e)}")
    
    def start_service(self):
        service_name = self.service_name_input.text()
        if not service_name:
            QMessageBox.warning(self, "Hata", "Servis adı giriniz!")
            return
        
        try:
            win32serviceutil.StartService(service_name)
            QMessageBox.information(self, "Başarılı", f"{service_name} servisi başlatıldı!")
            self.refresh_services()
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Servis başlatılamadı: {str(e)}")
    
    def stop_service(self):
        service_name = self.service_name_input.text()
        if not service_name:
            QMessageBox.warning(self, "Hata", "Servis adı giriniz!")
            return
        
        try:
            win32serviceutil.StopService(service_name)
            QMessageBox.information(self, "Başarılı", f"{service_name} servisi durduruldu!")
            self.refresh_services()
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Servis durdurulamadı: {str(e)}")
    
    def restart_service(self):
        service_name = self.service_name_input.text()
        if not service_name:
            QMessageBox.warning(self, "Hata", "Servis adı giriniz!")
            return
        
        try:
            win32serviceutil.RestartService(service_name)
            QMessageBox.information(self, "Başarılı", f"{service_name} servisi yeniden başlatıldı!")
            self.refresh_services()
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Servis yeniden başlatılamadı: {str(e)}")
    
    def change_startup_type(self):
        service_name = self.service_name_input.text()
        if not service_name:
            QMessageBox.warning(self, "Hata", "Servis adı giriniz!")
            return
        
        startup_type = self.startup_combo.currentText()
        try:
            if startup_type == "Otomatik":
                win32serviceutil.ChangeServiceConfig(
                    service_name, startType=win32service.SERVICE_AUTO_START
                )
            elif startup_type == "Manuel":
                win32serviceutil.ChangeServiceConfig(
                    service_name, startType=win32service.SERVICE_DEMAND_START
                )
            else:  # Devre Dışı
                win32serviceutil.ChangeServiceConfig(
                    service_name, startType=win32service.SERVICE_DISABLED
                )
            
            QMessageBox.information(self, "Başarılı", f"{service_name} servisi başlangıç türü değiştirildi!")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Başlangıç türü değiştirilemedi: {str(e)}")
    
    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

class DiskManagementWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Disk Yönetimi")
        self.setGeometry(200, 200, 1000, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QHBoxLayout()
        central_widget.setLayout(layout)
        
        # Sol taraf - Disk bilgileri
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setLayout(left_layout)
        
        self.disk_info = QTextEdit()
        self.disk_info.setReadOnly(True)
        self.disk_info.setMinimumWidth(400)
        left_layout.addWidget(self.disk_info)
        
        layout.addWidget(left_widget)
        
        # Sağ taraf - Disk işlemleri
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_widget.setLayout(right_layout)
        
        # Disk seçimi
        disk_select_group = QGroupBox("Disk Seçimi")
        disk_select_layout = QVBoxLayout()
        
        self.disk_combo = QComboBox()
        self.update_disk_list()
        disk_select_layout.addWidget(self.disk_combo)
        
        disk_select_group.setLayout(disk_select_layout)
        right_layout.addWidget(disk_select_group)
        
        # Disk temizleme
        cleanup_group = QGroupBox("Disk Temizleme")
        cleanup_layout = QVBoxLayout()
        
        btn_cleanup = QPushButton("Disk Temizleme")
        btn_cleanup.clicked.connect(self.disk_cleanup)
        cleanup_layout.addWidget(btn_cleanup)
        
        cleanup_group.setLayout(cleanup_layout)
        right_layout.addWidget(cleanup_group)
        
        # Disk birleştirme
        defrag_group = QGroupBox("Disk Birleştirme")
        defrag_layout = QVBoxLayout()
        
        btn_defrag = QPushButton("Disk Birleştir")
        btn_defrag.clicked.connect(self.disk_defrag)
        defrag_layout.addWidget(btn_defrag)
        
        defrag_group.setLayout(defrag_layout)
        right_layout.addWidget(defrag_group)
        
        # Disk sağlığı
        health_group = QGroupBox("Disk Sağlığı")
        health_layout = QVBoxLayout()
        
        btn_health = QPushButton("Sağlık Kontrolü")
        btn_health.clicked.connect(self.check_disk_health)
        health_layout.addWidget(btn_health)
        
        btn_smart = QPushButton("SMART Bilgileri")
        btn_smart.clicked.connect(self.check_smart_info)
        health_layout.addWidget(btn_smart)
        
        health_group.setLayout(health_layout)
        right_layout.addWidget(health_group)
        
        # Yenile butonu
        btn_refresh = QPushButton("Bilgileri Yenile")
        btn_refresh.clicked.connect(self.refresh_disk_info)
        right_layout.addWidget(btn_refresh)
        
        right_layout.addStretch()
        layout.addWidget(right_widget)
        
        # Disk bilgilerini göster
        self.refresh_disk_info()
    
    def update_disk_list(self):
        try:
            self.disk_combo.clear()
            for partition in psutil.disk_partitions():
                if partition.device and partition.mountpoint:
                    self.disk_combo.addItem(f"{partition.device} ({partition.mountpoint})")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Disk listesi alınamadı: {str(e)}")
    
    def refresh_disk_info(self):
        try:
            self.disk_info.clear()
            self.disk_info.append("=== Disk Bilgileri ===\n")
            
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    
                    self.disk_info.append(f"Sürücü: {partition.device}")
                    self.disk_info.append(f"Bağlantı Noktası: {partition.mountpoint}")
                    self.disk_info.append(f"Dosya Sistemi: {partition.fstype}")
                    self.disk_info.append(f"Toplam Alan: {format_bytes(usage.total)}")
                    self.disk_info.append(f"Kullanılan Alan: {format_bytes(usage.used)}")
                    self.disk_info.append(f"Boş Alan: {format_bytes(usage.free)}")
                    self.disk_info.append(f"Kullanım Oranı: %{usage.percent}")
                    
                    # Disk performans bilgileri
                    try:
                        disk_io = psutil.disk_io_counters(perdisk=True)
                        if partition.device.strip(":\\") in disk_io:
                            io = disk_io[partition.device.strip(":\\")]
                            self.disk_info.append(f"Okuma Sayısı: {io.read_count}")
                            self.disk_info.append(f"Yazma Sayısı: {io.write_count}")
                            self.disk_info.append(f"Okunan Veri: {format_bytes(io.read_bytes)}")
                            self.disk_info.append(f"Yazılan Veri: {format_bytes(io.write_bytes)}")
                    except:
                        pass
                    
                    self.disk_info.append("-" * 50)
                except:
                    continue
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Disk bilgileri alınamadı: {str(e)}")
    
    def disk_cleanup(self):
        selected_disk = self.disk_combo.currentText().split(" ")[0]
        try:
            # Windows Disk Cleanup aracını çalıştır
            subprocess.run(['cleanmgr', '/sagerun:1', '/d', selected_disk], check=True)
            QMessageBox.information(self, "Başarılı", "Disk temizleme işlemi başlatıldı!")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Disk temizleme başlatılamadı: {str(e)}")
    
    def disk_defrag(self):
        selected_disk = self.disk_combo.currentText().split(" ")[0]
        try:
            # Windows Disk Birleştirme aracını çalıştır
            subprocess.run(['defrag', selected_disk, '/A'], check=True)
            QMessageBox.information(self, "Başarılı", "Disk birleştirme işlemi başlatıldı!")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Disk birleştirme başlatılamadı: {str(e)}")
    
    def check_disk_health(self):
        selected_disk = self.disk_combo.currentText().split(" ")[0]
        try:
            # CHKDSK aracını çalıştır
            subprocess.run(['chkdsk', selected_disk, '/F'], check=True)
            QMessageBox.information(self, "Başarılı", "Disk sağlık kontrolü başlatıldı!")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Disk sağlık kontrolü başlatılamadı: {str(e)}")
    
    def check_smart_info(self):
        selected_disk = self.disk_combo.currentText().split(" ")[0]
        try:
            # WMIC ile SMART bilgilerini al
            result = subprocess.run(['wmic', 'diskdrive', 'get', 'status'], capture_output=True, text=True)
            
            self.disk_info.clear()
            self.disk_info.append("=== SMART Bilgileri ===\n")
            self.disk_info.append(result.stdout)
            
            if "OK" in result.stdout:
                self.disk_info.append("\nDisk durumu: Sağlıklı")
            else:
                self.disk_info.append("\nDisk durumu: Kontrol edilmeli!")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"SMART bilgileri alınamadı: {str(e)}")

class FileAuditWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Dosya İzleme ve Denetim")
        self.setGeometry(200, 200, 1000, 600)
        
        self.observer = None
        self.watching = False
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QHBoxLayout()
        central_widget.setLayout(layout)
        
        # Sol taraf - İzleme ayarları
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setLayout(left_layout)
        
        # Klasör seçimi
        folder_group = QGroupBox("İzlenecek Klasör")
        folder_layout = QVBoxLayout()
        
        folder_select_layout = QHBoxLayout()
        self.folder_input = QLineEdit()
        self.folder_input.setPlaceholderText("Klasör yolu...")
        btn_browse = QPushButton("Gözat")
        btn_browse.clicked.connect(self.browse_folder)
        folder_select_layout.addWidget(self.folder_input)
        folder_select_layout.addWidget(btn_browse)
        folder_layout.addLayout(folder_select_layout)
        
        # İzleme seçenekleri
        self.check_created = QCheckBox("Dosya Oluşturma")
        self.check_modified = QCheckBox("Dosya Değiştirme")
        self.check_deleted = QCheckBox("Dosya Silme")
        self.check_renamed = QCheckBox("Dosya Yeniden Adlandırma")
        
        for check in [self.check_created, self.check_modified, 
                     self.check_deleted, self.check_renamed]:
            check.setChecked(True)
            folder_layout.addWidget(check)
        
        folder_group.setLayout(folder_layout)
        left_layout.addWidget(folder_group)
        
        # Kontrol butonları
        control_group = QGroupBox("Kontroller")
        control_layout = QVBoxLayout()
        
        self.btn_start = QPushButton("İzlemeyi Başlat")
        self.btn_start.clicked.connect(self.start_monitoring)
        control_layout.addWidget(self.btn_start)
        
        self.btn_stop = QPushButton("İzlemeyi Durdur")
        self.btn_stop.clicked.connect(self.stop_monitoring)
        self.btn_stop.setEnabled(False)
        control_layout.addWidget(self.btn_stop)
        
        btn_clear = QPushButton("Günlüğü Temizle")
        btn_clear.clicked.connect(self.clear_log)
        control_layout.addWidget(btn_clear)
        
        control_group.setLayout(control_layout)
        left_layout.addWidget(control_group)
        
        left_layout.addStretch()
        layout.addWidget(left_widget)
        
        # Sağ taraf - İzleme günlüğü
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_widget.setLayout(right_layout)
        
        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
        right_layout.addWidget(self.log_viewer)
        
        layout.addWidget(right_widget)
    
    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "İzlenecek Klasörü Seç")
        if folder:
            self.folder_input.setText(folder)
    
    def start_monitoring(self):
        folder = self.folder_input.text()
        if not folder:
            QMessageBox.warning(self, "Hata", "Lütfen bir klasör seçin!")
            return
        
        if not os.path.exists(folder):
            QMessageBox.warning(self, "Hata", "Seçilen klasör bulunamadı!")
            return
        
        try:
            class FileHandler(FileSystemEventHandler):
                def __init__(self, window):
                    self.window = window
                
                def on_created(self, event):
                    if not event.is_directory and self.window.check_created.isChecked():
                        self.window.log_event(f"✨ Dosya Oluşturuldu: {event.src_path}")
                
                def on_modified(self, event):
                    if not event.is_directory and self.window.check_modified.isChecked():
                        self.window.log_event(f"📝 Dosya Değiştirildi: {event.src_path}")
                
                def on_deleted(self, event):
                    if not event.is_directory and self.window.check_deleted.isChecked():
                        self.window.log_event(f"❌ Dosya Silindi: {event.src_path}")
                
                def on_moved(self, event):
                    if not event.is_directory and self.window.check_renamed.isChecked():
                        self.window.log_event(
                            f"📋 Dosya Yeniden Adlandırıldı:\n"
                            f"Eski: {event.src_path}\n"
                            f"Yeni: {event.dest_path}"
                        )
            
            self.observer = Observer()
            self.observer.schedule(FileHandler(self), folder, recursive=True)
            self.observer.start()
            
            self.watching = True
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
            self.log_event(f"📡 İzleme başlatıldı: {folder}")
            
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"İzleme başlatılamadı: {str(e)}")
    
    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            
            self.watching = False
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.log_event("🛑 İzleme durduruldu")
    
    def log_event(self, message):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_viewer.append(f"[{current_time}] {message}")
    
    def clear_log(self):
        self.log_viewer.clear()
    
    def closeEvent(self, event):
        if self.watching:
            self.stop_monitoring()
        event.accept()

class DriverManagementWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sürücü Yönetimi")
        self.setGeometry(200, 200, 1000, 600)
        
        # WMI bağlantısını sınıf değişkeni olarak sakla
        self.wmi = None
        self.driver_cache = {}
        self.last_cache_update = 0
        self.cache_timeout = 5  # 5 saniye cache süresi
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QHBoxLayout()
        central_widget.setLayout(layout)
        
        # Sol taraf - Sürücü listesi
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setLayout(left_layout)
        
        # Arama kutusu
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Sürücü ara...")
        self.search_input.textChanged.connect(self.filter_drivers)
        search_layout.addWidget(self.search_input)
        left_layout.addLayout(search_layout)
        
        # Sürücü listesi
        self.driver_list = QTextEdit()
        self.driver_list.setReadOnly(True)
        self.driver_list.setMinimumWidth(400)
        left_layout.addWidget(self.driver_list)
        
        layout.addWidget(left_widget)
        
        # Sağ taraf - Sürücü işlemleri
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_widget.setLayout(right_layout)
        
        # Sürücü bilgileri
        info_group = QGroupBox("Sürücü Bilgileri")
        info_layout = QVBoxLayout()
        
        self.driver_info = QTextEdit()
        self.driver_info.setReadOnly(True)
        info_layout.addWidget(self.driver_info)
        
        info_group.setLayout(info_layout)
        right_layout.addWidget(info_group)
        
        # Sürücü işlemleri
        actions_group = QGroupBox("Sürücü İşlemleri")
        actions_layout = QVBoxLayout()
        
        btn_backup = QPushButton("Sürücüyü Yedekle")
        btn_backup.clicked.connect(self.backup_driver)
        actions_layout.addWidget(btn_backup)
        
        btn_restore = QPushButton("Sürücüyü Geri Yükle")
        btn_restore.clicked.connect(self.restore_driver)
        actions_layout.addWidget(btn_restore)
        
        btn_update = QPushButton("Güncellemeleri Kontrol Et")
        btn_update.clicked.connect(self.check_updates)
        actions_layout.addWidget(btn_update)
        
        btn_disable = QPushButton("Sürücüyü Devre Dışı Bırak")
        btn_disable.clicked.connect(self.disable_driver)
        actions_layout.addWidget(btn_disable)
        
        btn_enable = QPushButton("Sürücüyü Etkinleştir")
        btn_enable.clicked.connect(self.enable_driver)
        actions_layout.addWidget(btn_enable)
        
        actions_group.setLayout(actions_layout)
        right_layout.addWidget(actions_group)
        
        # Yenile butonu
        btn_refresh = QPushButton("Sürücüleri Yenile")
        btn_refresh.clicked.connect(self.force_refresh_drivers)
        right_layout.addWidget(btn_refresh)
        
        layout.addWidget(right_widget)
        
        # Otomatik güncelleme için timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_drivers)
        self.refresh_timer.start(5000)  # 5 saniyede bir güncelle
        
        # İlk sürücü listesini yükle
        self.init_wmi()
        self.refresh_drivers()
    
    def init_wmi(self):
        """WMI bağlantısını başlat"""
        try:
            import wmi
            self.wmi = wmi.WMI()
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"WMI bağlantısı kurulamadı: {str(e)}")
    
    def refresh_drivers(self):
        """Sürücüleri yenile (cache kullanarak)"""
        current_time = time.time()
        
        # Cache süresi dolmamışsa ve cache boş değilse, cache'den göster
        if (current_time - self.last_cache_update < self.cache_timeout and 
            self.driver_cache):
            self.display_drivers(self.driver_cache)
            return
        
        self.force_refresh_drivers()
    
    def force_refresh_drivers(self):
        """Sürücüleri zorla yenile (cache'i güncelle)"""
        try:
            if not self.wmi:
                self.init_wmi()
            
            self.driver_cache = {}
            for driver in self.wmi.Win32_SystemDriver():
                self.driver_cache[driver.Name] = {
                    'DisplayName': driver.DisplayName,
                    'State': driver.State,
                    'StartMode': driver.StartMode
                }
            
            self.last_cache_update = time.time()
            self.display_drivers(self.driver_cache)
            
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Sürücüler listelenirken hata oluştu: {str(e)}")
    
    def display_drivers(self, drivers):
        """Sürücüleri görüntüle"""
        self.driver_list.clear()
        
        for name, info in drivers.items():
            self.driver_list.append(f"Sürücü: {info['DisplayName']}")
            self.driver_list.append(f"Sistem Adı: {name}")
            self.driver_list.append(f"Durum: {info['State']}")
            self.driver_list.append(f"Başlangıç Türü: {info['StartMode']}")
            self.driver_list.append("-" * 50)
    
    def filter_drivers(self):
        """Sürücüleri filtrele"""
        search_text = self.search_input.text().lower()
        
        if not self.driver_cache:
            self.refresh_drivers()
            return
        
        filtered_drivers = {}
        for name, info in self.driver_cache.items():
            if (search_text in info['DisplayName'].lower() or 
                search_text in name.lower()):
                filtered_drivers[name] = info
        
        self.display_drivers(filtered_drivers)
    
    def backup_driver(self):
        try:
            backup_dir = QFileDialog.getExistingDirectory(self, "Yedekleme Klasörünü Seç")
            if backup_dir:
                # DISM ile sürücü yedekleme (arka planda çalıştır)
                process = subprocess.Popen(
                    ['dism.exe', '/online', '/export-driver', f'/destination:{backup_dir}'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                QMessageBox.information(self, "Bilgi", "Yedekleme işlemi başlatıldı...")
                
                # İşlem tamamlandığında bilgi ver
                def check_process():
                    if process.poll() is not None:
                        self.refresh_timer.stop()
                        QMessageBox.information(self, "Başarılı", "Sürücüler yedeklendi!")
                        self.refresh_timer.start()
                
                # İşlemi kontrol et
                QTimer.singleShot(1000, check_process)
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Yedekleme hatası: {str(e)}")
    
    def restore_driver(self):
        try:
            restore_dir = QFileDialog.getExistingDirectory(self, "Yedek Klasörünü Seç")
            if restore_dir:
                # DISM ile sürücü geri yükleme (arka planda çalıştır)
                process = subprocess.Popen(
                    ['dism.exe', '/online', '/add-driver', f'/driver:{restore_dir}', '/recurse'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                QMessageBox.information(self, "Bilgi", "Geri yükleme işlemi başlatıldı...")
                
                # İşlem tamamlandığında bilgi ver
                def check_process():
                    if process.poll() is not None:
                        self.refresh_timer.stop()
                        QMessageBox.information(self, "Başarılı", "Sürücüler geri yüklendi!")
                        self.force_refresh_drivers()
                        self.refresh_timer.start()
                
                # İşlemi kontrol et
                QTimer.singleShot(1000, check_process)
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Geri yükleme hatası: {str(e)}")
    
    def check_updates(self):
        try:
            # Windows Update ile sürücü güncellemelerini kontrol et (arka planda)
            process = subprocess.Popen(
                ['wusa.exe', '/detectnow'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            QMessageBox.information(self, "Bilgi", "Güncellemeler kontrol ediliyor...")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Güncelleme kontrolü hatası: {str(e)}")
    
    def disable_driver(self):
        try:
            driver_name = QInputDialog.getText(self, "Sürücü Devre Dışı Bırak", 
                                             "Sürücü sistem adını girin:")[0]
            if driver_name and driver_name in self.driver_cache:
                for driver in self.wmi.Win32_SystemDriver(Name=driver_name):
                    driver.ChangeStartMode("Disabled")
                    driver.Stop()
                QMessageBox.information(self, "Başarılı", "Sürücü devre dışı bırakıldı!")
                self.force_refresh_drivers()
            else:
                QMessageBox.warning(self, "Hata", "Geçersiz sürücü adı!")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Devre dışı bırakma hatası: {str(e)}")
    
    def enable_driver(self):
        try:
            driver_name = QInputDialog.getText(self, "Sürücü Etkinleştir", 
                                             "Sürücü sistem adını girin:")[0]
            if driver_name and driver_name in self.driver_cache:
                for driver in self.wmi.Win32_SystemDriver(Name=driver_name):
                    driver.ChangeStartMode("Auto")
                    driver.Start()
                QMessageBox.information(self, "Başarılı", "Sürücü etkinleştirildi!")
                self.force_refresh_drivers()
            else:
                QMessageBox.warning(self, "Hata", "Geçersiz sürücü adı!")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Etkinleştirme hatası: {str(e)}")
    
    def closeEvent(self, event):
        """Pencere kapatıldığında timer'ı durdur"""
        self.refresh_timer.stop()
        event.accept()

class MatrixRainDrop:
    def __init__(self, x, y, speed, char):
        self.x = x
        self.y = y
        self.speed = speed
        self.char = char
        self.opacity = 255

class MatrixBackground(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,./<>?"
        self.drops = []
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_matrix)
        self.timer.start(30)  # Daha hızlı güncelleme
        self.init_drops()

    def init_drops(self):
        # Daha fazla damla ekle
        drop_count = int(self.width() / 15)  # Ekran genişliğine göre damla sayısı
        for i in range(drop_count):
            x = random.randint(0, self.width())
            y = random.randint(-500, 0)  # Ekranın üstünden başla
            speed = random.randint(3, 8)  # Daha hızlı düşme
            char = random.choice(self.chars)
            self.drops.append(MatrixRainDrop(x, y, speed, char))

    def update_matrix(self):
        for drop in self.drops:
            drop.y += drop.speed
            if random.random() < 0.2:  # Karakter değişim olasılığını artır
                drop.char = random.choice(self.chars)
            if drop.y > self.height():
                drop.y = random.randint(-50, 0)
                drop.x = random.randint(0, self.width())
                drop.char = random.choice(self.chars)
                drop.speed = random.randint(3, 8)  # Yeni hız ata
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Daha koyu arka plan
        painter.fillRect(self.rect(), QColor(0, 0, 0, 230))
        
        # Matrix karakterleri
        font = QFont('Courier New', 16)  # Daha büyük font
        painter.setFont(font)
        
        for drop in self.drops:
            # Ana karakter (parlak)
            color = QColor(0, 255, 0, random.randint(180, 255))  # Daha parlak
            painter.setPen(color)
            painter.drawText(QRect(drop.x, drop.y, 20, 20), Qt.AlignCenter, drop.char)
            
            # İz efekti (soluk karakterler)
            for i in range(1, 6):  # İz uzunluğunu artır
                if drop.y - i * 20 > 0:
                    fade_color = QColor(0, 255, 0, random.randint(30, 100))  # Soluk yeşil
                    painter.setPen(fade_color)
                    painter.drawText(
                        QRect(drop.x, drop.y - i * 20, 20, 20),
                        Qt.AlignCenter,
                        random.choice(self.chars)
                    )

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.drops.clear()
        self.init_drops()

class AdminToolGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Sistem Yönetim Konsolu")
        self.setGeometry(100, 100, 400, 600)
        
        # Matrix arka planı
        self.matrix_background = MatrixBackground(self)
        
        # Ana widget ve layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)
        main_widget.setLayout(layout)
        
        # Matrix arka planını ana pencereye boyutlandır
        self.matrix_background.setGeometry(self.rect())
        
        self.setStyleSheet("""
            QMainWindow {
                background-color: transparent;
            }
            QWidget {
                background-color: rgba(43, 43, 43, 180);
            }
            QPushButton {
                background-color: rgba(44, 62, 80, 200);
                color: #00ff00;
                border: 2px solid #00ff00;
                padding: 15px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
                margin: 5px;
                text-align: left;
                padding-left: 20px;
            }
            QPushButton:hover {
                background-color: rgba(52, 73, 94, 220);
                border-color: #00ff99;
                color: #00ff99;
            }
            QPushButton:pressed {
                background-color: rgba(44, 62, 80, 250);
                border-color: #00cc00;
                color: #00cc00;
                padding-top: 16px;
                padding-bottom: 14px;
            }
            QPushButton:disabled {
                background-color: rgba(26, 26, 26, 180);
                border-color: #404040;
                color: #404040;
            }
            QPushButton:focus {
                border: 2px solid #00ffff;
                color: #00ffff;
            }
            QLabel {
                color: #00ff00;
                font-size: 14px;
            }
            QStatusBar {
                background-color: rgba(26, 26, 26, 180);
                color: #00ff00;
                padding: 8px;
                font-size: 12px;
                border-top: 1px solid #00ff00;
            }
            QGroupBox {
                border: 2px solid #00ff00;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                color: #00ff00;
                background-color: rgba(43, 43, 43, 180);
            }
            QGroupBox::title {
                color: #00ff00;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLineEdit {
                background-color: rgba(26, 26, 26, 180);
                color: #00ff00;
                border: 2px solid #00ff00;
                border-radius: 4px;
                padding: 5px;
            }
            QLineEdit:focus {
                border-color: #00ffff;
            }
            QTextEdit {
                background-color: rgba(26, 26, 26, 180);
                color: #00ff00;
                border: 2px solid #00ff00;
                border-radius: 4px;
            }
            QScrollArea {
                background-color: transparent;
                border: none;
            }
            QScrollBar:vertical {
                border: none;
                background-color: rgba(43, 43, 43, 180);
                width: 10px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background-color: #00ff00;
                border-radius: 5px;
                min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
            QComboBox {
                background-color: rgba(26, 26, 26, 180);
                color: #00ff00;
                border: 2px solid #00ff00;
                border-radius: 4px;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border: 2px solid #00ff00;
                width: 8px;
                height: 8px;
                background: #00ff00;
            }
        """)
        
        # Başlık
        title = QLabel("Windows Sistem Yönetim Konsolu")
        title.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 20px;
            color: #00ff00;
            border-bottom: 2px solid #00ff00;
            padding-bottom: 10px;
            background-color: transparent;
        """)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Butonlar için scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QWidget#scrollContents {
                background-color: transparent;
            }
        """)
        
        scroll_widget = QWidget()
        scroll_widget.setObjectName("scrollContents")
        scroll_layout = QVBoxLayout()
        scroll_widget.setLayout(scroll_layout)
        
        # Butonlar
        buttons_data = [
            ("💻 Sistem Bilgileri", self.show_system_info),
            ("📊 Performans İzleme", self.show_performance),
            ("🔐 Şifre Güvenliği", self.show_security),
            ("🌐 Ağ Trafiği Analizi", self.show_network),
            ("🔍 ARP Kontrolü", self.show_arp),
            ("🔍 DNS Güvenliği", self.show_dns),
            ("🔌 Port Tarama", self.show_port_scanner),
            ("👥 Kullanıcı Yönetimi", self.show_user_management),
            ("⚙️ Servis Yönetimi", self.show_service_management),
            ("💾 Disk Yönetimi", self.show_disk_management),
            ("👁️ Dosya İzleme ve Denetim", self.show_file_audit),
            ("🔧 Sürücü Yönetimi", self.show_driver_management)
        ]
        
        for text, callback in buttons_data:
            btn = QPushButton(text)
            btn.clicked.connect(callback)
            btn.setMinimumHeight(50)
            btn.setCursor(Qt.PointingHandCursor)
            scroll_layout.addWidget(btn)
        
        scroll_layout.addStretch()
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)
        
        # Durum çubuğu
        self.statusBar().showMessage("Sistem Hazır | Güvenlik Durumu: Aktif")
        
        # Pencere ayarları
        self.setMinimumWidth(500)
        self.setMinimumHeight(700)
    
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.matrix_background.setGeometry(self.rect())
    
    def show_system_info(self):
        self.system_info_window = SystemInfoWindow(self)
        self.system_info_window.show()
    
    def show_performance(self):
        self.performance_window = PerformanceWindow(self)
        self.performance_window.show()
    
    def show_security(self):
        self.security_window = SecurityWindow(self)
        self.security_window.show()
    
    def show_network(self):
        self.network_window = NetworkAnalyzerWindow(self)
        self.network_window.show()
    
    def show_arp(self):
        self.arp_window = ARPCheckerWindow(self)
        self.arp_window.show()
    
    def show_dns(self):
        self.dns_window = DNSSecurityWindow(self)
        self.dns_window.show()
    
    def show_port_scanner(self):
        self.port_scanner_window = PortScannerWindow(self)
        self.port_scanner_window.show()
    
    def show_user_management(self):
        self.user_management_window = UserManagementWindow(self)
        self.user_management_window.show()
    
    def show_service_management(self):
        self.service_management_window = ServiceManagementWindow(self)
        self.service_management_window.show()
    
    def show_disk_management(self):
        self.disk_management_window = DiskManagementWindow(self)
        self.disk_management_window.show()
    
    def show_file_audit(self):
        self.file_audit_window = FileAuditWindow(self)
        self.file_audit_window.show()
    
    def show_driver_management(self):
        self.driver_management_window = DriverManagementWindow(self)
        self.driver_management_window.show()

def format_bytes(bytes):
    """Byte değerini okunaklı formata çevirir"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024
    return f"{bytes:.2f} PB"

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Yönetici izni kontrolü için ctypes import
    import ctypes
    
    # Yönetici olarak çalışmıyorsa ve Windows'ta isek
    if sys.platform == 'win32' and not ctypes.windll.shell32.IsUserAnAdmin():
        # Yönetici olarak yeniden başlatma
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()
    
    window = AdminToolGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()