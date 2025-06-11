document.addEventListener('DOMContentLoaded', function() {
    const copyButtons = document.querySelectorAll('.copy-button');

    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
         
            const codeBlock = this.parentElement.querySelector('pre code');
            if (codeBlock) {
                const textToCopy = codeBlock.innerText;

          
                navigator.clipboard.writeText(textToCopy)
                    .then(() => {
   
                        const originalSvg = this.innerHTML; 
                        this.innerHTML = `
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                            </svg>
                        `;
                        const originalTitle = this.title;
                        this.title = "Copied!";

          
                        setTimeout(() => {
                            this.innerHTML = originalSvg;
                            this.title = originalTitle;
                        }, 2000);
                    })
                    .catch(err => {
                      
                        console.error('Failed to copy text: ', err);
                        alert('Failed to copy code. Please copy manually.');
                    });
            }
        });
    });
});