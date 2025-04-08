import hashlib
import json
import time


class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_transactions = []

        # Create genesis block
        self.create_block(proof=1, previous_hash='0')

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.pending_transactions,
            'proof': proof,
            'previous_hash': previous_hash
        }

        # Reset pending transactions
        self.pending_transactions = []

        # Add block to chain
        self.chain.append(block)
        return block

    def get_last_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False

        while not check_proof:
            hash_operation = hashlib.sha256(str(new_proof ** 2 - previous_proof ** 2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1

        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1

        while block_index < len(chain):
            block = chain[block_index]

            # Check if previous_hash matches the hash of the previous block
            if block['previous_hash'] != self.hash(previous_block):
                return False

            # Check if proof of work is correct
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof ** 2 - previous_proof ** 2).encode()).hexdigest()

            if hash_operation[:4] != '0000':
                return False

            previous_block = block
            block_index += 1

        return True

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)
        return self.get_last_block()['index'] + 1

    def mine(self):
        previous_block = self.get_last_block()
        previous_proof = previous_block['proof']

        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)

        block = self.create_block(proof, previous_hash)
        return block



    def get_all_data(self):
        # Extract password data from all blocks
        password_data = []
        for block in self.chain:
            for transaction in block['transactions']:
                if 'service' in transaction and 'username' in transaction and 'password' in transaction:
                    password_data.append({
                        'service': transaction['service'],
                        'username': transaction['username'],
                        'password': transaction['password'],
                        'password_hash': transaction.get('password_hash', ''),
                        'timestamp': transaction.get('timestamp', 0)
                    })
        return password_data