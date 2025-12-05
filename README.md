# PCPSI

PCPSI is a client–server Private Set Intersection (PSI) implementation based on Homomorphic Encryption (HE).  
It uses Microsoft SEAL (BFV scheme) and performs PSI over real TCP communication between two machines.

This project is intended for research, experimentation, and performance evaluation of end-to-end PSI protocols.

---

## 1. Clone the Repository

```bash
git clone https://github.com/ehdwn95713/PCPSI.git
```

## 2. Install Microsoft SEAL Library
```bash
cd HE
./install_seal.sh
```

## 3. Build Protocol
```bash
cd ..
cd src
./build.sh
```

## 4. Evaluation



