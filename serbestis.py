# import subprocess
#
# hash_file = "hashlar.txt"
# dictionary_file = "sozluk.txt"
# command = ["hashcat", "-m", "0", "-a", "0", hash_file, dictionary_file]
#
# subprocess.run(command)
# import hashlib
#
# def hash_cracker(hash_to_crack, dictionary_file):
#     with open(dictionary_file, 'r') as file:
#         for line in file:
#             word = line.strip()
#             hashed_word = hashlib.md5(word.encode()).hexdigest()
#             if hashed_word == hash_to_crack:
#                 return word
#     return None
#
# hash_to_crack = "5d41402abc4b2a76b9719d911017c592"  # "hello" sözünün MD5 hash-i
# dictionary_file = "sozluk.txt"
#
# result = hash_cracker(hash_to_crack, dictionary_file)
# if result:
#     print(f"Şifrə tapıldı: {result}")
# else:
#     print("Şifrə tapılmadı.")

import os
import subprocess


# Hash faylı yaratmaq funksiyası
def create_hash_file(passwords, hash_algorithm="sha256", output_file="hashes.txt"):
    """
    Verilən parollar siyahısından hash faylı yaradılır.

    :param passwords: Parolların siyahısı
    :param hash_algorithm: Hash alqoritmi (md5, sha256 və s.)
    :param output_file: Hash faylının adı
    """
    import hashlib

    with open(output_file, "w") as file:
        for password in passwords:
            if hash_algorithm.lower() == "md5":
                hashed = hashlib.md5(password.encode()).hexdigest()
            elif hash_algorithm.lower() == "sha256":
                hashed = hashlib.sha256(password.encode()).hexdigest()
            else:
                raise ValueError("Dəstəklənməyən hash alqoritmi!")

            file.write(hashed + "\n")
    print(f"{output_file} faylı yaradıldı!")


# Hashcat üçün komandaların icrası
def run_hashcat(hash_file, wordlist, output_file="cracked_passwords.txt"):
    """
    Hashcat ilə parolları qırır.

    :param hash_file: Hash faylının adı
    :param wordlist: Sözlük faylı (wordlist.txt)
    :param output_file: Nəticə faylının adı
    """
    try:
        command = [
            "hashcat",
            "-m", "0",  # Hashcat üçün MD5 (0), SHA-256 (1400) və s. modellər
            hash_file,
            wordlist,
            "-o", output_file
        ]
        subprocess.run(command, check=True)
        print(f"Nəticələr {output_file} faylında saxlanıldı!")
    except FileNotFoundError:
        print("Hashcat tapılmadı! Əvvəlcə quraşdırın.")
    except subprocess.CalledProcessError as e:
        print(f"Hashcat icrasında xəta baş verdi: {e}")


# Əsas hissə
if __name__ == "__main__":
    # 1. Parol siyahısı
    passwords = ["password123", "qwerty", "admin123", "letmein", "welcome"]

    # 2. Hash faylını yarat
    create_hash_file(passwords, hash_algorithm="md5", output_file="hashes.txt")

    # 3. Hashcat ilə qırma
    wordlist_path = "wordlist.txt"  # Buraya sözlük faylının yolunu əlavə edin
    if os.path.exists(wordlist_path):
        run_hashcat("hashes.txt", wordlist_path)
    else:
        print("Sözlük faylı tapılmadı! Əvvəlcə wordlist faylı hazırlayın.")


