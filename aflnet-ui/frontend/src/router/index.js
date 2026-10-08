import { createRouter, createWebHistory } from 'vue-router'
import DashboardView from '../views/DashboardView.vue'
import ProtocolsView from '../views/ProtocolsView.vue'
import TasksView from '../views/TasksView.vue'
import TaskDetailView from '../views/TaskDetailView.vue'
import StateMachineView from '../views/StateMachineView.vue'
import FindingsView from '../views/FindingsView.vue'
import AnalysisView from '../views/AnalysisView.vue'
import ReportsView from '../views/ReportsView.vue'
import SettingsView from '../views/SettingsView.vue'

const routes = [
  { path: '/', component: DashboardView, meta: { title: '总览看板', eyebrow: 'OVERVIEW' } },
  { path: '/protocols', component: ProtocolsView, meta: { title: '检测任务', eyebrow: 'DETECTION JOBS' } },
  { path: '/tasks', component: TasksView, meta: { title: '任务列表', eyebrow: 'JOBS' } },
  { path: '/tasks/:id', component: TaskDetailView, meta: { title: '任务详情', eyebrow: 'JOB DETAIL' } },
  { path: '/analysis', component: AnalysisView, meta: { title: '异常分析', eyebrow: 'ANALYSIS' } },
  { path: '/state-machine', component: StateMachineView, meta: { title: '状态机分析', eyebrow: 'STATE MODEL' } },
  { path: '/findings', component: FindingsView, meta: { title: '异常回放', eyebrow: 'REPLAY' } },
  { path: '/reports', component: ReportsView, meta: { title: '报告中心', eyebrow: 'REPORTS' } },
  { path: '/settings', component: SettingsView, meta: { title: '系统设置', eyebrow: 'SETTINGS' } },
]

export default createRouter({ history: createWebHistory(), routes })
