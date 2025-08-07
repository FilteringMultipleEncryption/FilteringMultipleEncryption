# FME (Filtering‑with‑Multiple‑Encryption) Protocol

This source code is a Java implementation of the FME (Filtering‑with‑Multiple‑Encryption) protocol. 

---

## Purpose

The purpose of this source code is to reproduce our experimental results, in particular, **Fig. 6 "Proposal (Large ℓ)" and "Proposal (Small ℓ)"**. In this document, we explain how to reproduce them using the Foursquare and Amazon datasets. Our code does not require GPUs or a lot of cores/RAM and can be easily run on a laptop.

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

## Functionality

The following table shows an entry point for each data type: 

| Data Type       | Entry Point          | Output                   | Description              |
| --------------- | -------------------- | ------------------------ | ------------------------ |
| **Categorical** | `fme.CategoricalFME` | Frequency MSE            | Evaluate the FME protocol for categorical data (Section VI)|
| **Key–Value**   | `fme.KeyValueFME`    | Frequency MSE and Mean MSE | Evaluate the FME protocol for key–value data (Section VII)|

Each entry point has the following arguments:

| Argument                | Description                                   |
| ----------------------- | --------------------------------------------- |
| `DataConfig`            | Dataset name                                  |
| `epsilon`               | ε in differential privacy                     |
| `delta`                 | δ in differential privacy                     |
| `alpha`                 | Significance level                            |
| `beta`                  | Sampling probability                          |
| `topK`                  | Evaluate the MSE of the top-K frequent items. |
| `encryption`            | Encryption mode (`RSA` or `ECIES`)            |
| `isLargeL`              | Use Proposal (Large ℓ) if `true`. Use Proposal (Small ℓ) if `false` |
| `seed`                  | Random seed (optional)                        |

Therefore, we can run the FME protocol as follows:
- FME protocol for categorical data (Section VI)
   ```bash
      java -cp "lib/*:bin" fme.CategoricalFME `DataConfig` `epsilon` `delta` `alpha` `beta` `topK` `encryption` `isLargeL` `seed`
   ```

- FME protocol for key-value data (Section VII)
   ```bash
      java -cp "lib/*:bin" fme.KeyValueFME `DataConfig` `epsilon` `delta` `alpha` `beta` `topK` `encryption` `isLargeL` `seed`
   ```

See ``Usage (2)`` for their examples.

---

## Usage

Below, we explain how to reproduce Fig. 6 "Proposal (Large ℓ)" and "Proposal (Small ℓ)":

### (1) Installation and Compilation

1. Clone the repository:

   ```bash
   git clone https://github.com/FilteringMultipleEncryption/FilteringMultipleEncryption.git
   cd FilteringMultipleEncryption
   ```

2. Place the following libraries in the `lib/` directory:

   - **Apache Commons Math 3.6.1**:

     Download **`commons-math3-3.6.1-bin.zip`** or **`.tar.gz`** from the Apache archive and decompress it:
     - [commons-math3-3.6.1-bin.zip](https://archive.apache.org/dist/commons/math/binaries/commons-math3-3.6.1-bin.zip) (accessed on August 3, 2025)
     - [commons-math3-3.6.1-bin.tar.gz](https://archive.apache.org/dist/commons/math/binaries/commons-math3-3.6.1-bin.tar.gz) (accessed on August 3, 2025)
     
     The archive contains the file `commons-math3-3.6.1.jar`. Place it into the `lib/` directory.  
     (NOTE: Commons Math 4.x uses a different package structure and is incompatible with our code.)
   - **Bouncy Castle**:

     Our code works with **`bcprov-jdk18on-1.81.jar`**:
     - [bcprov-jdk18on-1.81.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.81/bcprov-jdk18on-1.81.jar) (accessed on August 3, 2025)

     Place it into the `lib/` directory.
     
3. Compile our code:

   ```bash
   javac -cp "lib/*" -d bin src/data/*.java src/encryption/*.java src/fme/*.java src/hash/*.java src/sageo/*.java src/util/*.java
   ```

### (2) Execution

### Foursquare Dataset

1. Download the following datasets into `data/`:
   - **[Global-scale Check-in Dataset](https://sites.google.com/site/yangdingqi/home/foursquare-dataset#h.p_ID_56)** — `dataset_TIST2015.zip`
   - **[User Profile Dataset](https://sites.google.com/site/yangdingqi/home/foursquare-dataset#h.p_ID_68)** — `dataset_UbiComp2016.zip`
   
   You may also place all the extracted `.txt` files from these ZIP archives directly into the `data/` directory instead of using the ZIP files. The program will work the same way in this case.
2. Run the preprocessing code as follows:

   On **Windows**:
      ```bash
      java -cp "lib/*;bin" util.DataPreprocessing foursquare
      ```
      
   On **Linux/MacOS**:
      ```bash
      java -cp "lib/*:bin" util.DataPreprocessing foursquare
      ```

3. Run the evaluation code as follows:

   On **Windows**:
   ```bash
   java -cp "lib/*;bin" fme.CategoricalFME foursquare 1.0 1E-12 0.05 1.0 50 RSA true 100
   ```
   
   On **Linux/MacOS**:
   ```bash
   java -cp "lib/*:bin" fme.CategoricalFME foursquare 1.0 1E-12 0.05 1.0 50 RSA true 100
   ```

**Results**: After running the code in step 3, the following results will be output to the console:

   ```bash
   Frequency MSE: 7.89673284955141E-8
   ```
   This is the MSE of "Proposal (Large ℓ)" with ε=1.0.

### Amazon Dataset

1. Place `ratings_Beauty.csv` (unzipped file) from the [Kaggle Amazon Ratings (Beauty Products)](https://www.kaggle.com/datasets/skillsmuggler/amazon-ratings) dataset into `data/`. \
   (NOTE: You need to log in to the Kaggle to download the dataset.)
2. Run preprocessing as follows:

   On **Windows**:
      ```bash
      java -cp "lib/*;bin" util.DataPreprocessing amazon
      ```
   
   On **Linux/MacOS**:
      ```bash
      java -cp "lib/*:bin" util.DataPreprocessing amazon
      ```

3. Run the evaluation code as follows:

   On **Windows**:
   ```bash
   java -cp "lib/*;bin" fme.KeyValueFME amazon 1.0 1E-12 0.05 1.0 50 RSA true 100
   ```
   
   On **Linux/MacOS**:
   ```bash
   java -cp "lib/*:bin" fme.KeyValueFME amazon 1.0 1E-12 0.05 1.0 50 RSA true 100
   ```

**Results**: After running the code in step 3, the following results will be output to the console:

   ```bash
   Frequency MSE: 3.338134642028916E-7
   Mean MSE: 0.1642468655220782
   ```
   They are the MSE (frequency) and the MSE (mean) of "Proposal (Large ℓ)" with ε=1.0.

For each data type, we can change the value of ε by changing the 2nd argument (from `1.0` to the desired value). \
We can evaluate "Proposal (Small ℓ)" by changing the 8th argument from `true` to `false`. \
The 9th argument (`100` in the above examples) is optional and can be omitted. \
We plotted Fig. 6 "Proposal (Large ℓ)" and "Proposal (Small ℓ)" in the Foursquare and Amazon datasets by changing ε from `0.1` to `5.0` and averaging the MSE over 10 runs.

---

## Execution Environment

We have verified the processing of our source code explained above using Windows 11 Pro and OpenJDK JDK 24.0.1.

---

## License

This repository is released under the MIT License. See `LICENSE` for details.
