import socket
import threading
import rsa
import hashlib
import json
import base64

public_key, private_key = rsa.newkeys(1024)
public_partner = None

IP = ""

choice = input("Do you want to host (1) or to connect (2)?")

if choice == "1":
  server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server.bind((IP, 9999))
  server.listen()

  client, _ = server.accept()

  client.send(public_key.save_pkcs1("PEM"))
  public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
elif choice == "2":
  client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  client.connect((IP, 9999))

  public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
  client.send(public_key.save_pkcs1("PEM"))
else:
  exit()


def sending_messages(socket):
  while True:
    message = input("")
    encrypted_msg = rsa.encrypt(message.encode(), public_partner)

    msg_hash = hashlib.sha256(message.encode()).hexdigest()
    signature = rsa.sign(msg_hash.encode(), private_key, 'SHA-256')
  
    message_obj = {
      "encrypted_msg": base64.b64encode(encrypted_msg).decode('utf-8'),
      "signature": base64.b64encode(signature).decode('utf-8')
    }

    socket.send(json.dumps(message_obj).encode())
    print("You: " + message)

def receiving_messages(socket, sender_public_key):
  while True:
    packet = json.loads(socket.recv(4096).decode())
    
    encrypted_msg = base64.b64decode(packet['encrypted_msg'])
    decrypted_msg = rsa.decrypt(encrypted_msg, private_key).decode()

    calculated_hash = hashlib.sha256(decrypted_msg.encode()).hexdigest()

    signature = base64.b64decode(packet['signature'])

    try:
      rsa.verify(calculated_hash.encode(), signature, sender_public_key)
      print("Partner: " + decrypted_msg)
    except:
      print("Integrity check failed!")


threading.Thread(target=sending_messages, args=(client,)).start()
threading.Thread(target=receiving_messages, args=(client, public_partner)).start()