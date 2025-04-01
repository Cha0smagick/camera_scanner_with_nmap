# Stealth IP Camera Scanner

![Security](https://img.shields.io/badge/Security-Pentesting-red)
![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

Herramienta avanzada para identificar cámaras IP accesibles públicamente en redes locales e internet, con soporte para escaneo mediante proxy.

## 📌 Descripción

Este escáner identifica cámaras de vigilancia IP que están accesibles sin autenticación o con credenciales por defecto. Está diseñado para:

- Auditorías de seguridad ética
- Pruebas de penetración en entornos autorizados
- Identificación de dispositivos vulnerables en redes propias

**⚠️ ADVERTENCIA:** Solo para uso legal y ético. El escaneo no autorizado de redes ajenas es ilegal.

## ✨ Características

- Escaneo multihilo de redes locales y rangos IP aleatorios
- Detección de más de 30 modelos de cámaras (Hikvision, Dahua, Axis, etc.)
- Soporte para múltiples protocolos (HTTP, RTSP, RTMP, ONVIF)
- Sistema de verificación con múltiples patrones y heurísticas
- Opción de escaneo mediante proxy (HTTP, HTTPS, SOCKS)
- Generación de informes con URLs de acceso detectadas

## 🛠 Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/tuusuario/camera_scanner_with_nmap.git
   cd camera_scanner_with_nmap

