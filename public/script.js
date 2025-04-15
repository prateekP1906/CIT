document.getElementById("menu-toggle").addEventListener("click", () => {
    const menu = document.getElementById("mobile-menu");
    menu.classList.toggle("hidden");
  });
  
  async function handleLookup(apiName) {
    try {
      const response = await fetch(`/api/${apiName}`);
      const data = await response.json();
      document.getElementById(`${apiName === "virustotal" ? "vt" : apiName === "Virustotal" ? "md" : "shodan"}-result`).textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      alert("Error fetching API data.");
      console.error(err);
    }
  }
