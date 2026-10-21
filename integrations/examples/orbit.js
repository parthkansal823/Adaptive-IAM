// Only presentation preferences and sample filtering live in the browser.
const root = document.documentElement
let savedTheme
try { savedTheme = localStorage.getItem('orbit-theme') } catch { /* Storage may be unavailable. */ }
const systemTheme = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
const setTheme = theme => {
  root.dataset.theme = theme
  for (const button of document.querySelectorAll('.theme-toggle')) {
    button.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`)
    button.setAttribute('title', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`)
    button.setAttribute('aria-pressed', String(theme === 'dark'))
  }
}
setTheme(['light','dark'].includes(savedTheme) ? savedTheme : systemTheme)
for (const button of document.querySelectorAll('.theme-toggle')) button.addEventListener('click', () => {
  const theme = root.dataset.theme === 'dark' ? 'light' : 'dark'
  setTheme(theme)
  try { localStorage.setItem('orbit-theme', theme) } catch { /* The theme still works in this tab. */ }
})
const search = document.querySelector('#project-search')
const status = document.querySelector('#project-status')
function filterProjects() {
  const query = search.value.trim().toLowerCase()
  const selectedStatus = status.value
  let count = 0
  for (const row of document.querySelectorAll('[data-project]')) {
    const visible = row.dataset.project.includes(query) && row.dataset.project.includes(selectedStatus)
    row.hidden = !visible
    if (visible) count++
  }
  document.querySelector('#project-count').textContent = `${count} sample project${count === 1 ? '' : 's'}`
  document.querySelector('.filter-empty').hidden = count !== 0
}
if (search && status) {
  const params = new URLSearchParams(location.search)
  search.value = (params.get('q') || '').slice(0, 100)
  const initialStatus = params.get('status') || ''
  if ([...status.options].some(option => option.value === initialStatus)) status.value = initialStatus
  filterProjects()
  search.addEventListener('input', filterProjects)
  status.addEventListener('change', filterProjects)
}
