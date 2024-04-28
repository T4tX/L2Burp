import threading
from scapy.all import sniff, wrpcap
import queue
import swap

queue_lock = threading.Lock()

stop_flag = False

# Функция для перехвата пакетов
def packet_sniffer(packet_queue):
    while True:
        sniff(prn=lambda pkt: packet_queue.put(pkt))  # sniff() будет помещать каждый перехваченный пакет в очередь
    print('process_packets stop')

# Функция для вывода пакетов из очереди на экран и их обработки
# def process_packets(packet_queue):
#     global stop_flag
#     while True:
#         with queue_lock:
#             if stop_flag:
#                 break
#         packet = packet_queue.get()  # Получаем пакет из очереди
        # print(packet.summary())  # Выводим краткую информацию о пакете
        # Добавьте вашу логику обработки пакета здесь
        # Например:
        # process_packet(packet)
        # wrpcap('corpus.pcap', packet, append=True)
    # print('process_packets stop')
    # sniffer_thread.join()
# Создаем общую очередь для передачи пакетов между потоками
packet_queue = queue.Queue()

# Создаем блокировку для обеспечения одновременного доступа только одного потока к очереди

# Функция для обработки пакетов с использованием блокировки
def process_with_lock(packet_queue):
    global stop_flag
    while not stop_flag:
        with queue_lock:
            if not packet_queue.empty():
                packet = packet_queue.get()  # Получаем пакет из очереди
                print(packet.summary())  # Выводим краткую информацию о пакете
                wrpcap('corpus.pcap', packet, append=True)
                # Добавьте вашу логику обработки пакета здесь
                # Например:
                # process_packet(packet)

# Создаем два потока - один для перехвата пакетов, другой для вывода их на экран и обработки
sniffer_thread = threading.Thread(target=packet_sniffer, args=(packet_queue,))
processor_thread = threading.Thread(target=process_with_lock, args=(packet_queue,))
web_thread = threading.Thread(target=swap.run_server)

# Запускаем оба потока
sniffer_thread.start()
processor_thread.start()
web_thread.start()
# Главный поток продолжит выполнение
# Вы можете добавить другие задачи здесь, которые будут выполняться параллельно с перехватом пакетов

# Ожидаем завершения работы обоих потоков (необязательно)
sniffer_thread.join()
processor_thread.join()
web_thread.join()