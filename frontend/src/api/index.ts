/**
 * API service functions — typed wrappers around the API client.
 */

import apiClient from './client';
import type {
  AuthConfig,
  LoginRequest,
  TokenResponse,
  UserInfo,
  DashboardSummary,
  DashboardActivity,
  Asset,
  AssetInput,
  Application,
  ApplicationInput,
  Policy,
  PolicyInput,
  AccessRequest,
  AccessRequestInput,
  Approval,
  AuditLog,
  DetailedHealth,
  PaginatedResponse,
} from '@/types';

export interface ListParams {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  [key: string]: string | number | boolean | undefined;
}

// --- Auth ---

export const authApi = {
  getConfig: () =>
    apiClient.get<AuthConfig>('/auth/config').then(r => r.data),

  login: (data: LoginRequest) =>
    apiClient.post<TokenResponse>('/auth/login', data).then(r => r.data),

  me: () =>
    apiClient.get<UserInfo>('/auth/me').then(r => r.data),
};

// --- Dashboard ---

export const dashboardApi = {
  getSummary: () =>
    apiClient.get<DashboardSummary>('/dashboard/summary').then(r => r.data),

  getActivity: (limit = 20) =>
    apiClient.get<DashboardActivity[]>('/dashboard/activity', { params: { limit } }).then(r => r.data),
};

// --- Assets ---

export const assetsApi = {
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<Asset>>('/assets', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get<Asset>(`/assets/${id}`).then(r => r.data),

  create: (data: Partial<AssetInput>) =>
    apiClient.post<Asset>('/assets', data).then(r => r.data),

  update: (id: string, data: Partial<AssetInput>) =>
    apiClient.patch<Asset>(`/assets/${id}`, data).then(r => r.data),

  delete: (id: string) =>
    apiClient.delete(`/assets/${id}`).then(r => r.data),
};

// --- Applications ---

export const applicationsApi = {
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<Application>>('/applications', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get<Application>(`/applications/${id}`).then(r => r.data),

  create: (data: Partial<ApplicationInput>) =>
    apiClient.post<Application>('/applications', data).then(r => r.data),

  update: (id: string, data: Partial<ApplicationInput>) =>
    apiClient.patch<Application>(`/applications/${id}`, data).then(r => r.data),

  delete: (id: string) =>
    apiClient.delete(`/applications/${id}`).then(r => r.data),
};

// --- Policies ---

export const policiesApi = {
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<Policy>>('/policies', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get<Policy>(`/policies/${id}`).then(r => r.data),

  create: (data: Partial<PolicyInput>) =>
    apiClient.post<Policy>('/policies', data).then(r => r.data),

  update: (id: string, data: Partial<PolicyInput>) =>
    apiClient.patch<Policy>(`/policies/${id}`, data).then(r => r.data),

  delete: (id: string) =>
    apiClient.delete(`/policies/${id}`).then(r => r.data),
};

// --- Access Requests ---

export const accessRequestsApi = {
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<AccessRequest>>('/access-requests', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get<AccessRequest>(`/access-requests/${id}`).then(r => r.data),

  create: (data: AccessRequestInput) =>
    apiClient.post<AccessRequest>('/access-requests', data).then(r => r.data),

  cancel: (id: string) =>
    apiClient.post<AccessRequest>(`/access-requests/${id}/cancel`).then(r => r.data),
};

// --- Approvals ---

export const approvalsApi = {
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<Approval>>('/approvals', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get<Approval>(`/approvals/${id}`).then(r => r.data),

  approve: (id: string, comment?: string) =>
    apiClient.post<Approval>(`/approvals/${id}/approve`, { comment }).then(r => r.data),

  reject: (id: string, comment: string) =>
    apiClient.post<Approval>(`/approvals/${id}/reject`, { comment }).then(r => r.data),
};

// --- Audit ---

export const auditApi = {
  list: (params?: ListParams) =>
    apiClient
      .get<PaginatedResponse<AuditLog>>('/audit', { params })
      .then(r => r.data),
};

// --- Health ---

export const healthApi = {
  detailed: () =>
    apiClient.get<DetailedHealth>('/health/detailed', { baseURL: import.meta.env.VITE_API_URL || '' }).then(r => r.data),
};
