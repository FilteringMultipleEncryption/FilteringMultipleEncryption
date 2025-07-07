# FME (Filtering‑with‑Multiple‑Encryption) Protocol

A Java implementation of the Filtering‑with‑Multiple‑Encryption (FME) protocol

---

## Directory Structure

```text
data/       ── Place raw datasets here (currently empty)
dataset/    ── Pre‑processed datasets (currently empty). The preprocessed files will be automatically stored in the dataset/ directory after running DataPreprocessing.
lib/        ── External libraries (JAR files) (currently empty)
src/        ── Java source code
LICENSE.txt ── MIT license
README.md   ── This file
```

---

## Usage

### Installation

1. **Clone the repository**

   ```bash
   git clone <repo‑url>
   cd fme
   ```

2. **Dependencies**

   Place the following libraries in the `lib/` directory:

   - [Apache Commons Math](https://commons.apache.org/proper/commons-math/) — Apache License 2.0
   - [Bouncy Castle](https://www.bouncycastle.org/) — MIT License

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
| `epsilon`               | ε for differential privacy                   |
| `delta`                 | δ for differential privacy                   |
| `alpha`                 | Significance level                           |
| `beta`                  | Sampling ratio                               |
| `topK`                  | Measure MSE of the top‑K most frequent items |
| `encryption`            | Encryption mode (`RSA`, …)                   |
| `isLargeL`              | Use Proposal (Large ℓ) if `true`             |

---

## Sample Execution

The following examples reproduce the settings of **Figure 6** in the paper. The evaluation results will be printed directly to the console (standard output).

### Foursquare Dataset

#### 1  Download & Pre‑process Data

1. Create a `data/` directory (if it does not exist) and download into `data/`:
   - **TIST2015** — [`dataset_TIST2015.zip`](https://sites.google.com/site/yangdingqi/home/foursquare-dataset#h.p_ID_56)
   - **UbiComp2016** — [`dataset_UbiComp2016.zip`](https://sites.google.com/site/yangdingqi/home/foursquare-dataset#h.p_ID_68)
2. Run preprocessing:

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

---

### Amazon Dataset

#### 1  Download & Pre‑process Data

1. Place `ratings_Beauty.csv` from the [Kaggle Amazon Ratings](https://www.kaggle.com/datasets/skillsmuggler/amazon-ratings) dataset into `data/`.
2. Preprocess:

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

---

## License

This repository is released under the MIT License. See `LICENSE` for details.

