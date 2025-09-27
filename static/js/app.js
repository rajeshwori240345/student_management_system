(function () {
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const storedTheme = localStorage.getItem('sms-theme');
  const root = document.documentElement;
  const toggleButton = document.getElementById('dark-mode-toggle');

  function setTheme(theme) {
    root.setAttribute('data-theme', theme);
    localStorage.setItem('sms-theme', theme);
  }

  setTheme(storedTheme || (prefersDark ? 'dark' : 'light'));

  if (toggleButton) {
    toggleButton.addEventListener('click', () => {
      const current = root.getAttribute('data-theme');
      setTheme(current === 'dark' ? 'light' : 'dark');
    });
  }

  window.renderGradeChart = function (data) {
    if (!data || !document.getElementById('gradeChart')) {
      return;
    }
    const labels = Object.keys(data);
    const counts = Object.values(data);
    const ctx = document.getElementById('gradeChart').getContext('2d');
    new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Students per grade',
          data: counts,
          backgroundColor: '#2563eb88',
          borderColor: '#2563eb',
          borderWidth: 1,
        }],
      },
      options: {
        responsive: true,
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              precision: 0,
            },
          },
        },
      },
    });
  };
})();
