import hashlib
import json
from time import time
from uuid import uuid4
from flask import Flask, jsonify, request, render_template
from urllib.parse import urlparse
import requests
import os

# --- NEW: Import cryptography modules for digital signatures ---
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# --- CONSTANTS ---
MINING_SENDER = "0"  # Address for the mining reward
MINING_REWARD = 1
CHAIN_DATA_FILE = "blockchain.json" # File to save the chain

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        
        self.load_chain_from_disk()

    def load_chain_from_disk(self):
        """Loads the chain and nodes from a file on disk."""
        try:
            with open(CHAIN_DATA_FILE, 'r') as f:
                data = json.load(f)
                self.chain = data['chain']
                self.nodes = set(data['nodes'])
                print(f"Loaded blockchain with {len(self.chain)} blocks from {CHAIN_DATA_FILE}")
        except (FileNotFoundError, json.JSONDecodeError):
            self.new_block(previous_hash='1', proof=100)
            self.save_chain_to_disk()
            print(f"No valid chain found, created new genesis block.")

    def save_chain_to_disk(self):
        """Saves the current chain and nodes to a file on disk."""
        data = {
            'chain': self.chain,
            'nodes': list(self.nodes)
        }
        with open(CHAIN_DATA_FILE, 'w') as f:
            json.dump(data, f, indent=4)
            
    def register_node(self, address):
        """Add a new node to the list of nodes."""
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)

    def new_block(self, proof, previous_hash):
        """Create a new Block in the Blockchain."""
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.current_transactions = []
        self.chain.append(block)
        self.save_chain_to_disk()
        return block

    def new_transaction(self, sender_public_key, recipient_address, amount, signature):
        """
        Creates a new transaction after verifying it.
        --- MODIFIED: Returns a tuple (success, message) ---
        """
        transaction_data = {
            'sender_public_key': sender_public_key,
            'recipient_address': recipient_address,
            'amount': amount
        }

        # Verification Step 1: Verify the signature
        if not self.verify_signature(sender_public_key, signature, transaction_data):
            return (False, "Invalid transaction signature.")

        # Verification Step 2: Verify the sender has enough funds
        sender_address = self.get_address_from_public_key(sender_public_key)
        if self.get_balance(sender_address) < amount:
            return (False, "Insufficient funds.")

        # Add the full transaction details
        self.current_transactions.append({**transaction_data, 'signature': signature})
        return (True, self.last_block['index'] + 1)

    def get_balance(self, address):
        """Calculate the balance for a given address."""
        balance = 0
        for block in self.chain:
            for tx in block['transactions']:
                tx_sender_address = self.get_address_from_public_key(tx.get('sender_public_key'))
                if tx_sender_address == address:
                    balance -= tx['amount']
                if tx.get('recipient_address') == address:
                    balance += tx['amount']
        return balance

    def broadcast_transaction(self, transaction):
        """Broadcasts a transaction to all nodes in the network."""
        for node in self.nodes:
            try:
                requests.post(f'http://{node}/transactions/receive', json=transaction)
            except requests.exceptions.ConnectionError:
                print(f"Warning: Could not connect to node {node} to broadcast transaction.")
    
    @staticmethod
    def get_address_from_public_key(public_key_hex):
        """Generates a simple address from a public key hex string."""
        if public_key_hex is None or public_key_hex == MINING_SENDER:
            return MINING_SENDER
        return hashlib.sha256(public_key_hex.encode()).hexdigest()

    @staticmethod
    def verify_signature(public_key_hex, signature_hex, transaction_data):
        """Verify a signature for a given transaction."""
        if public_key_hex == MINING_SENDER:
            return True
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            signature = bytes.fromhex(signature_hex)
            message = json.dumps(transaction_data, sort_keys=True).encode()
            public_key.verify(signature, message)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """Creates a SHA-256 hash of a Block."""
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        """Simple Proof of Work Algorithm."""
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """Validates the Proof: Does hash(last_proof, proof) contain 4 leading zeroes?"""
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def valid_chain(self, chain):
        """Determine if a given blockchain is valid."""
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False
            if not self.valid_proof(last_block['proof'], block['proof']):
                return False
            last_block = block
            current_index += 1
        return True

    def resolve_conflicts(self):
        """Consensus Algorithm: replaces our chain with the longest valid one in the network."""
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']
                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except requests.exceptions.ConnectionError:
                print(f"Warning: Could not connect to node {node} for consensus.")

        if new_chain:
            self.chain = new_chain
            self.save_chain_to_disk()
            return True
        return False

# --- Instantiate the Node and Blockchain ---
app = Flask(__name__)
node_identifier = str(uuid4()).replace('-', '')
blockchain = Blockchain()

# --- NEW: Wallet & Signature Helper Functions ---
def sign_transaction(private_key_hex, transaction_data):
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    message = json.dumps(transaction_data, sort_keys=True).encode()
    signature = private_key.sign(message)
    return signature.hex()

# === API ENDPOINTS ===

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/mine', methods=['POST'])
def mine():
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block['proof'])

    node_address = blockchain.get_address_from_public_key(node_identifier)
    blockchain.current_transactions.append({
        'sender_public_key': MINING_SENDER,
        'recipient_address': node_address,
        'amount': MINING_REWARD,
        'signature': 'mining_reward'
    })

    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged!",
        'index': block['index'],
    }
    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def handle_new_transaction():
    values = request.get_json()
    required = ['private_key', 'recipient_address', 'amount']
    if not all(k in values for k in required):
        return jsonify({'message': 'Missing required fields.'}), 400

    try:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(values['private_key']))
        public_key = private_key.public_key()
        public_key_hex = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()

        transaction_data = {
            'sender_public_key': public_key_hex,
            'recipient_address': values['recipient_address'],
            'amount': int(values['amount'])
        }
        
        signature_hex = sign_transaction(values['private_key'], transaction_data)
        
        # --- MODIFIED: Handle the new tuple return format ---
        success, message = blockchain.new_transaction(
            public_key_hex,
            values['recipient_address'],
            int(values['amount']),
            signature_hex
        )

        if not success:
            return jsonify({'message': message}), 400
            
        full_transaction = {**transaction_data, 'signature': signature_hex}
        blockchain.broadcast_transaction(full_transaction)

        response = {'message': f'Transaction queued for Block {message}'}
        return jsonify(response), 201

    except (ValueError, TypeError):
        return jsonify({'message': 'Invalid private key format.'}), 400

@app.route('/transactions/receive', methods=['POST'])
def receive_transaction():
    """Endpoint for other nodes to send transactions to."""
    values = request.get_json()
    required = ['sender_public_key', 'recipient_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return jsonify({'message': 'Missing transaction data'}), 400

    # --- MODIFIED: Handle the new tuple return format ---
    success, message = blockchain.new_transaction(
        values['sender_public_key'],
        values['recipient_address'],
        values['amount'],
        values['signature']
    )
    if not success:
        return jsonify({'message': f'Received transaction rejected: {message}'}), 400
    
    return jsonify({'message': 'Transaction added to pool.'}), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    return jsonify({'chain': blockchain.chain, 'length': len(blockchain.chain)}), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return jsonify({'message': "Error: Please supply a valid list of nodes"}), 400
    for node in nodes:
        blockchain.register_node(node)
    
    blockchain.save_chain_to_disk()
    response = {'message': 'New nodes have been added', 'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {'message': 'Our chain was replaced', 'new_chain': blockchain.chain}
    else:
        response = {'message': 'Our chain is authoritative', 'chain': blockchain.chain}
    return jsonify(response), 200

# === Wallet Management Endpoints ===
@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_key_hex = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()
    
    public_key_hex = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()

    address = blockchain.get_address_from_public_key(public_key_hex)

    return jsonify({
        'private_key': private_key_hex,
        'public_key': public_key_hex,
        'address': address
    }), 200

@app.route('/wallet/balance', methods=['GET'])
def get_wallet_balance():
    address = request.args.get('address')
    if not address:
        return jsonify({'message': 'Missing address parameter'}), 400
    
    balance = blockchain.get_balance(address)
    return jsonify({'address': address, 'balance': balance}), 200

if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.run(host='0.0.0.0', port=port)
