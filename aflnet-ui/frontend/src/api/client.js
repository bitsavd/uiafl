import axios from 'axios'

const http = axios.create({ baseURL: '/api', timeout: 20000 })

http.interceptors.response.use(
  response => response,
  error => {
    const detail = error.response?.data?.detail
    throw new Error(detail || error.message || '请求失败')
  },
)

export const api = {
  health: () => http.get('/health'),
  settings: () => http.get('/settings'),
  saveSettings: payload => http.put('/settings', payload),
  protocols: () => http.get('/protocols'),
  checkTarget: payload => http.post('/targets/check', payload),
  tasks: () => http.get('/tasks'),
  createTask: payload => http.post('/tasks', payload),
  task: id => http.get(`/tasks/${id}`),
  startTask: id => http.post(`/tasks/${id}/start`),
  stopTask: id => http.post(`/tasks/${id}/stop`),
  removeTask: id => http.delete(`/tasks/${id}`),
  findings: id => http.get(`/tasks/${id}/findings`),
  replay: (id, payload) => http.post(`/tasks/${id}/replay`, payload),
  report: id => http.get(`/tasks/${id}/report.md`),
  reportPdfUrl: id => `/api/tasks/${id}/report.pdf`,
  stateMachineUrl: id => `/api/tasks/${id}/state-machine?ts=${Date.now()}`,
}
