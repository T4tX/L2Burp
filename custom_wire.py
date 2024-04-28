import threading
from scapy.all import sniff

# Функция для перехвата пакетов
def packet_sniffer():
    sniff(prn=process_packet)  # sniff() будет вызывать функцию process_packet для каждого перехваченного пакета

# Функция для обработки пакетов
def process_packet(packet):
    print(packet.summary())  # Выводим краткую информацию о пакете
    # Добавьте вашу логику обработки пакета здесь

# Создаем два потока - один для перехвата пакетов, другой для их обработки
sniffer_thread = threading.Thread(target=packet_sniffer)
sniffer_thread.start()

# Главный поток продолжит выполнение
# Вы можете добавить другие задачи здесь, которые будут выполняться параллельно с перехватом пакетов

# Ожидаем завершения потока перехвата пакетов (необязательно)
sniffer_thread.join()