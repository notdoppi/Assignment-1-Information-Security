(() => {
    "use strict";
    const categoryOptions = {
        id_card: {
            accept: ".png,.jpg,.jpeg",
            help: "Choose an identity or insurance image (PNG or JPEG)."
        },
        document: {
            accept: ".pdf,.doc,.docx,.xls,.xlsx",
            help: "Choose a PDF, Word document, or Excel spreadsheet."
        },
        video: {
            accept: ".mp4",
            help: "Choose an MP4 health video."
        }
    };
    function initUploadCategoryPicker() {
        const categorySelect = document.getElementById("file_type");
        const fileInput = document.getElementById("file");
        const fileHelp = document.getElementById("file-help");

        if (!categorySelect || !fileInput || !fileHelp) {
            return;
        }
        function updateFileTypes() {
            const option = categoryOptions[categorySelect.value];
            if (!option) return;

            fileInput.accept = option.accept;
            fileHelp.textContent = option.help;
            fileInput.value = "";
        }
        categorySelect.addEventListener("change", updateFileTypes);
        updateFileTypes();
    }
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initUploadCategoryPicker);
    } else {
        initUploadCategoryPicker();
    }
})();
