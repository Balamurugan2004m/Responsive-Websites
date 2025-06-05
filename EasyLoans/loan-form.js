document.addEventListener('DOMContentLoaded', function() {
    const loanTypeSelect = document.getElementById('loanType');
    const othersInputDiv = document.getElementById('othersInput');

    loanTypeSelect.addEventListener('change', function() {
        const selected = this.value.trim();
        othersInputDiv.style.display = selected === 'Others' ? 'block' : 'none';
    });
});
