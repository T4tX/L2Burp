from flask import Flask, render_template, request,redirect,url_for,flash
from scapy.all import *
from scapy.contrib import *
from scapy.layers.all import *
from scapy.config import conf
import os
import custom_wire_2


conf.use_pcap = True
app = Flask(__name__)


app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


repeater = []
@app.route('/')
def index():
    packet = rdpcap('corpus.pcap')

    return render_template('index4.html', packet=packet)

@app.route('/repeater', methods = ["GET"])
def repeater_add():
    return redirect(url_for('index'))


@app.route('/stop', methods = ["POST"])
def stop():
    global stop_flag
    custom_wire_2.sniffer_thread.interrupt()    
    return redirect(url_for('index'))

@app.route('/clear', methods = ["POST"])
def clear():
    os.remove("corpus.pcap")
    return redirect(url_for('index'))

@app.route('/swap', methods = ["POST"])
def swap():
    #sudo setcap cap_net_raw=eip ./swap.py
    #sudo setcap cap_net_raw,cap_net_admin=eip /path/to/scapy

    pkt = request.form.get('command')
    print(pkt)
    try:
        sendp(pkt,iface='eth0')
        flash('Sucsessful!')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Error {e}')
        return redirect(url_for('index'))



def run_server():
    app.run()
if __name__ == '__main__':
    app.run()