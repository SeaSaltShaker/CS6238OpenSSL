pip install pyopenssl
pip install pycryptodome
These two modules are required to run the code

Run the code in this order:
1. cert_auth.py address port
2. threeS_server.py CA_addr CA_port server_addr server_port
3. client.py svr_address svr_port CA_addr CA_port

When you run client.py, it asks you to input a username, then you can run the methods