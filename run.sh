#!/bin/bash

echo "ChatWithBackdoor A iniciar..."

# Verificar se os ficheiros existem
if [ ! -f "server.py" ]; then
    echo "[ERRO] server.py não encontrado!"
    exit 1
fi

if [ ! -f "client.py" ]; then
    echo "[ERRO] client.py não encontrado!"
    exit 1
fi

# Detectar terminal disponível e abrir servidor
echo "[INFO] A iniciar servidor..."
if command -v gnome-terminal &> /dev/null; then
    gnome-terminal -- bash -c "python3 server.py; exec bash"
elif command -v xterm &> /dev/null; then
    xterm -e "python3 server.py" &
elif command -v konsole &> /dev/null; then
    konsole -e python3 server.py &
elif command -v mate-terminal &> /dev/null; then
    mate-terminal -- bash -c "python3 server.py; exec bash" &
elif command -v xfce4-terminal &> /dev/null; then
    xfce4-terminal -e "python3 server.py" &
else
    echo "[ERRO] Nenhum terminal gráfico encontrado!"
    echo "Terminais suportados: gnome-terminal, xterm, konsole, mate-terminal, xfce4-terminal"
    exit 1
fi

# Esperar pelo servidor 
sleep 2

# Abrir cliente
echo "[INFO] A iniciar cliente..."
if command -v gnome-terminal &> /dev/null; then
    gnome-terminal -- bash -c "python3 client.py; exec bash"
elif command -v xterm &> /dev/null; then
    xterm -e "python3 client.py" &
elif command -v konsole &> /dev/null; then
    konsole -e python3 client.py &
elif command -v mate-terminal &> /dev/null; then
    mate-terminal -- bash -c "python3 client.py; exec bash" &
elif command -v xfce4-terminal &> /dev/null; then
    xfce4-terminal -e "python3 client.py" &
fi

echo "Servidor e cliente iniciados!"