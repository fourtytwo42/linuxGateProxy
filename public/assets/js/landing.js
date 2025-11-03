const resourceGrid = document.getElementById('resource-grid');

function createCard(resource) {
  const column = document.createElement('div');
  column.className = 'column is-one-third';
  column.innerHTML = `
    <div class="card resource-card">
      <div class="card-content">
        <p class="title is-4">${resource.name}</p>
        <p class="subtitle is-6">${resource.description || ''}</p>
        <button class="button is-link is-fullwidth" data-id="${resource.id}">Open</button>
      </div>
    </div>
  `;
  column.querySelector('button').addEventListener('click', () => {
    window.location.href = `/resource/${resource.id}`;
  });
  return column;
}

async function loadResources() {
  const response = await fetch('/api/resources');
  if (!response.ok) {
    resourceGrid.innerHTML = '<p>Unable to load resources.</p>';
    return;
  }
  const { resources } = await response.json();
  if (!resources || resources.length === 0) {
    resourceGrid.innerHTML = '<p>No resources available.</p>';
    return;
  }
  resources.forEach((resource) => resourceGrid.appendChild(createCard(resource)));
}

loadResources();

