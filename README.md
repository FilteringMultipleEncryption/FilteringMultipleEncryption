# FME (Filtering‑with‑Multiple‑Encryption) Protocol

This source code is a Java implementation of the FME (Filtering‑with‑Multiple‑Encryption) protocol.

---

## Purpose

The purpose of this source code is to reproduce our experimental results, in particular, **Figure 6 "Proposal (Large ℓ)" and "Proposal (Small ℓ)"**. They are the MSEs (Mean Squared Errors) of our protocols, which are our main experimental results. In this document, we explain how to reproduce them using the Foursquare and Amazon datasets. See **Usage** for details.

---

## Directory Structure

```text
data/       ── Place raw datasets here (currently empty).
dataset/    ── Preprocessed datasets (currently empty). The preprocessed files will be automatically stored in the dataset/ directory after running DataPreprocessing.
lib/        ── External libraries (JAR files) (currently empty).
src/        ── Java source code.
LICENSE.txt ── MIT license.
README.md   ── This file.
```

---

## Usage

### Installation

1. **Clone the repository**

   ```bash
   git clone <repo‑url>
   cd FilteringMultipleEncryption
   ```

2. **Dependencies**

   Place the following libraries in the `lib/` directory:

   - [Apache Commons Math 3.6.1](https://archive.apache.org/dist/commons/math/binaries/)  
     Download **`commons-math3-3.6.1-bin.zip`** or **`.tar.gz`** from the Apache archive and decompress it.  
     The archive contains the file `commons-math3-3.6.1.jar`. Place it into the `lib/` directory.  
     *(NOTE: Commons Math 4.x uses a different package structure and is incompatible with our code.)*
     
   - [Bouncy Castle](https://www.bouncycastle.org/)  
     Our code works with **`bcprov-jdk18on-1.81.jar`**.  
     Place it into the `lib/` directory.

---

### Compilation

```bash
javac -cp "lib/*" -d bin src/data/*.java src/encryption/*.java src/fme/*.java src/hash/*.java src/sageo/*.java src/util/*.java

```

---

### Execution

| Variant         | Entry point          | Description              |
| --------------- | -------------------- | ------------------------ |
| **Categorical** | `fme.CategoricalFME` | FME for categorical data |
| **Key–Value**   | `fme.KeyValueFME`    | FME for key–value data   |

Both classes expose an `execute` method with the following arguments:

| Argument                | Description                                  |
| ----------------------- | -------------------------------------------- |
| `DataConfig`            | Dataset name                                 |
| `epsilon`               | ε in differential privacy                    |
| `delta`                 | δ in differential privacy                    |
| `alpha`                 | Significance level                           |
| `beta`                  | Sampling ratio                               |
| `topK`                  | Measure MSE of the top‑K most frequent items |
| `encryption`            | Encryption mode (`RSA`, …)                   |
| `isLargeL`              | Use Proposal (Large ℓ) if `true`             |

---

## Sample Execution

The following examples reproduce **Figure 6 "Proposal (Large ℓ)" and "Proposal (Small ℓ)"** in our paper. The evaluation results will be printed directly to the console (standard output).

### Foursquare Dataset

#### 1  Download & Pre‑process Data

1. Download the following datasets into `data/`:
   - **TIST2015** — [`dataset_TIST2015.zip`](https://sites.google.com/site/yangdingqi/home/foursquare-dataset#h.p_ID_56)
   - **UbiComp2016** — [`dataset_UbiComp2016.zip`](https://sites.google.com/site/yangdingqi/home/foursquare-dataset#h.p_ID_68)
2. Run preprocessing as follows:

On **Windows**:
   ```bash
   java -cp "lib/*;bin" util.DataPreprocessing foursquare
   ```
   
On **Linux/MacOS**:
   ```bash
   java -cp "lib/*:bin" util.DataPreprocessing foursquare
   ```

#### 2  Run Evaluation

On **Windows**:
```bash
java -cp "lib/*;bin" fme.CategoricalFME foursquare 1.0 1E-12 0.05 1.0 50 RSA true
```

On **Linux/MacOS**:
```bash
java -cp "lib/*:bin" fme.CategoricalFME foursquare 1.0 1E-12 0.05 1.0 50 RSA true
```

Then, the MSE of "Proposal (Large ℓ)" with ε=1.0 will be output to the console. 
To change the value of ε, change the 2nd argument (from `1.0` to the desired value). 
To evaluate "Proposal (Small ℓ)", change the 8th argument from `true` to `false`.

---

### Amazon Dataset

#### 1  Download & Pre‑process Data

1. Place `ratings_Beauty.csv` (unzipped file) from the [Kaggle Amazon Ratings](https://www.kaggle.com/datasets/skillsmuggler/amazon-ratings) dataset into `data/`. 
   *(NOTE: you need to log in to the Kaggle to download the dataset.)
2. Run preprocessing as follows:

On **Windows**:
   ```bash
   java -cp "lib/*;bin" util.DataPreprocessing amazon
   ```

On **Linux/MacOS**:
   ```bash
   java -cp "lib/*:bin" util.DataPreprocessing amazon
   ```
   
#### 2  Run Evaluation

On **Windows**:
```bash
java -cp "lib/*;bin" fme.KeyValueFME amazon 1.0 1E-12 0.05 1.0 50 RSA true
```

On **Linux/MacOS**:
```bash
java -cp "lib/*:bin" fme.KeyValueFME amazon 1.0 1E-12 0.05 1.0 50 RSA true
```

Then, the MSE (frequency) and the MSE (mean) of "Proposal (Large ℓ)" with ε=1.0 will be output to the console. 
To change the value of ε, change the 2nd argument (from `1.0` to the desired value). 
To evaluate "Proposal (Small ℓ)", change the 8th argument from `true` to `false`.

---

## License

This repository is released under the MIT License. See `LICENSE` for details.

