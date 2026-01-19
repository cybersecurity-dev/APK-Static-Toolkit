<div align="center">
    <p align="center">
        <a href="https://wikipedia.org/wiki/Apk_(file_format)">
         <img width="35%" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/Android.svg" />
        </a>
    </p>

# **`APK Static Toolkit`** | _Android Package Kit (APK) Analysing Toolkit_
</div>

[![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://source.android.com/)
[![YouTube](https://img.shields.io/badge/YouTube-%23FF0000.svg?style=for-the-badge&logo=YouTube&logoColor=white)](https://youtube.com/playlist?list=PL9V4Zu3RroiVIEtSO4i4VLlfMJqppvxvh&si=MTyY7rk1Bu5R0ncD) 
[![Reddit](https://img.shields.io/badge/Reddit-FF4500?style=for-the-badge&logo=reddit&logoColor=white)](https://www.reddit.com/r/androiddev/new/)

<p align="center">
    <a href="https://github.com/cybersecurity-dev/"><img height="25" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/github.svg" alt="GitHub"></a>
    &nbsp;
    <a href="https://www.youtube.com/@CyberThreatDefence"><img height="25" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/youtube.svg" alt="YouTube"></a>
    &nbsp;
    <a href="https://cyberthreatdefence.com/my_awesome_lists"><img height="20" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/blog.svg" alt="My Awesome Lists"></a>
    <img src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/bar.gif">
</p>

[![made-with-python](http://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
[![built-for-android](https://forthebadge.com/images/badges/built-for-android.svg)](https://www.android.com/)
[![built-with-science](https://forthebadge.com/images/badges/built-with-science.svg)](https://cyberthreatdefence.com/)
[![open-source](https://forthebadge.com/images/badges/open-source.svg)](https://cyberthreatdefence.com/)

<details>
 
 <summary>Install required tools on Linux</summary>
 
 ### For Ubuntu 18.04, 20.04, 22.04
 
 ```bash
 sudo apt-get update
 ```
 </details>
 
 
 <details>
 
 <summary>Install required python libs</summary>
 
 ### pip install
 ```bash
 python -m venv w_apk
 source w_apk/bin/activate
 pip install --upgrade pip
 pip install -r requirements.txt
 ```
 
 ### conda install
 ```bash
 conda config --add channels conda-forge
 conda install --file requirements_conda.txt
 ```
 
 </details>


```mermaid
graph TD
    A["APK"]
    B["Manifest<br>(AndroidManifest.xml)"]
    C["Signatures<br>(META-INF)"]
    D["Assets<br>(assets/)"]
    E["Compiled resources<br>(resources.arsc)"]
    F["Native libraries<br>(lib/)"]
    G["Dalvik bytecode<br>(classes.dex)"]
    H["Resources<br>(res/)"]
    
    A --> B
    A --> C
    A --> D
    A --> E
    A --> F
    A --> G
    A --> H
```
**Explanation of the components:**

* **Manifest (AndroidManifest.xml):** Contains essential information about the application, such as its package name, components (activities, services, etc.), permissions, and hardware/software requirements.
* **Signatures (META-INF/):** Directory containing the signature files used to verify the integrity and authenticity of the APK.
* **Assets (assets/):** Directory containing application assets, such as raw data files, that are not compiled into resources.
* **Compiled resources (resources.arsc):** A compiled resource file that indexes and contains all the non-code resources of the application (e.g., strings, layouts, drawables).
* **Native libraries (lib/):** Directory containing compiled code that is specific to a particular device's processor architecture (e.g., .so files).
* **Dalvik bytecode (classes.dex):** Contains the compiled Java code of the application, optimized for the Dalvik or ART (Android Runtime) virtual machine.
* **Resources (res/):** Directory containing the application's resources, such as layouts, drawables (images), strings, and values (colors, dimensions, etc.). These resources are typically compiled into `resources.arsc`.
<p align="center" href="https://www.android.com/"> 
<a href="https://www.android.com/"><picture><img width="50%" height="auto" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/apk.svg" height="175px" alt="APK"/></picture></a>
</p>


## Extraction Framework

|           | Regex | Androguard | aapt | pyaxmlparser | apktool |
| :-------- | :------: | :----: | :-: | :----: | :----: |
| Strings Extractor   |     [✅](https://github.com/cybersecurity-dev/APK-Static-Toolkit/blob/main/Strings%20Extractor/apk_strings_extractor.py)   |   ☐    |  ☐  |   ☐   |     ☐      |      ☐      | 
| Permission Extractor     |     ☐     |   ☐    |  ☐  |    ☐     |     ☐      |     ☐      | 
| CFG Extractor   |    ☐    |   [✅](https://github.com/cybersecurity-dev/APK-Static-Toolkit/blob/main/APK%20CFG%20Extractor/apk_cfg_extractor_wandroguard.py)    |  ☐  |   ☐    |     ☐      |     ☐      | 
| FCG Extractor   |    ☐    |   [✅](https://github.com/cybersecurity-dev/APK-Static-Toolkit/blob/main/APK%20FCG%20Extractor/apk_fcg_extractor_wandroguard.py)    |  ☐  |   ☐    |     ☐      |     ☐      | 

##

### My Awesome Lists
You can access the my other awesome lists [here](https://cyberthreatdefence.com/my_awesome_lists)

### Contributing

[Contributions of any kind welcome, just follow the guidelines](contributing.md)!

### Contributors

[Thanks goes to these contributors](https://github.com/cybersecurity-dev/APK-Static-Toolkit/graphs/contributors)!

[🔼 Back to top](#apk-static-toolkit--android-package-kit-apk-analysing-toolkit)
