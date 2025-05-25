from Stage_2 import ctr_decrypt
import sys
from datetime import datetime



def brute_force_saes_ctr(ciphertext, known_plaintext_fragment, nonce=0, max_keys_to_try=65536, log_file=None):
    """
    Brute force S-AES CTR encryption with clean file logging.
    
    Args:
        ciphertext: Encrypted bytes
        known_plaintext_fragment: Text or bytes pattern to find
        nonce: Encryption nonce (default 0)
        max_keys_to_try: Maximum keys to test (default 65536)
        log_file: Path to output file (None for console only)
        
    Returns:
        List of (key, decrypted_data) tuples
    """
    potential_matches = []
    
    # Convert to bytes if needed
    if isinstance(known_plaintext_fragment, str):
        known_plaintext_fragment = known_plaintext_fragment.encode()
    
    # Setup output redirection
    original_stdout = sys.stdout
    if log_file:
        sys.stdout = open(log_file, 'w')
    
    try:
        print(f"Brute Force Attack - {datetime.now()}")
        print(f"Searching for: {known_plaintext_fragment}\n")
        
        for key in range(0, max_keys_to_try):
            try:
                decrypted = ctr_decrypt(ciphertext, key, nonce)
                
                if known_plaintext_fragment in decrypted:
                    match = (hex(key), decrypted)
                    potential_matches.append(match)
                    print(f"\nMATCH FOUND - Key: {hex(key)}")
                    print("-" * 40)
                    
                    # Try to show text preview
                    try:
                        text_preview = decrypted[:200].decode('utf-8', errors='replace')
                        print(f"Text Preview:\n{text_preview}")
                    except:
                        print("Binary Data (first 50 bytes):")
                        print(decrypted[:50])
                    
                    print(f"\nData Length: {len(decrypted)} bytes")
                    print("-" * 40)
                    
            except Exception:
                continue
                
            # Progress update
            if key % 5000 == 0:
                print(f"Progress: {key}/{max_keys_to_try} keys tested", end='\r')
        
        # Final report
        print(f"\n\nCOMPLETED: Found {len(potential_matches)} matches")
        for i, (key, _) in enumerate(potential_matches, 1):
            print(f"{i}. Key: {key}")
            
    finally:
        if log_file:
            sys.stdout.close()
            sys.stdout = original_stdout
            print(f"Results saved to {log_file}")
    
    return potential_matches

if __name__ == "__main__":
    # Load encrypted file
    with open('encrypted.bin', 'rb') as f:
        ciphertext = f.read()
    
    # Configure your search
    known_text = "hi"  # Text or bytes to find
    output_file = "decryption_log.txt"  # Set to None for console output
    
    # Run the attack
    matches = brute_force_saes_ctr(
        ciphertext,
        known_plaintext_fragment=known_text,
        log_file=output_file
    )
    
    # Console summary
    if output_file and matches:
        print("\nDiscovered Keys:")
        for key, _ in matches:
            print(f"- {key}")