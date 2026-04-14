# Attribution and External Projects

This project, **PrivaDB**, integrates and builds upon several external projects. We are grateful to the authors and contributors of these projects for their work.

## External Projects

### 1. Project Foxhound
- **URL**: [https://github.com/SAP/project-foxhound](https://github.com/SAP/project-foxhound)
- **Author**: SAP
- **Description**: A Firefox-based browser with dynamic taint tracking for detecting privacy leaks.
- **Integration**: Used as the research foundation and engine for dynamic analysis.

### 2. Comparative-Privacy-Analysis
- **URL**: [https://github.com/eleumasc/Comparative-Privacy-Analysis](https://github.com/eleumasc/Comparative-Privacy-Analysis)
- **Author**: [eleumasc](https://github.com/eleumasc)
- **Description**: A framework for detecting persistent web tracking via storage APIs.
- **Integration**: The core logic in `Web/src/scratch_new` is based on the analytical framework and detection heuristics from this project. We have modified and integrated the logic to specifically target IndexedDB and fit the PrivaDB dashboard architecture.

## Licensing
Please refer to the original repositories for their respective license agreements. This project is intended for research and educational purposes.
