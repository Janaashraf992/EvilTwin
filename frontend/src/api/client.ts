import axios from "axios";
import { useAuthStore } from "../store/authStore";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ??
  `${window.location.protocol}//${window.location.hostname}:8000`;

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30_000
});

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let _refreshPromise: Promise<void> | null = null;

async function _refreshTokens(): Promise<void> {
  const refreshToken = useAuthStore.getState().refreshToken;
  if (!refreshToken) throw new Error("no refresh token");

  const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
    refresh_token: refreshToken,
  });

  const { access_token, refresh_token } = response.data;
  useAuthStore.getState().updateTokens(access_token, refresh_token);
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry && originalRequest.url !== '/auth/login') {
      originalRequest._retry = true;

      try {
        // Deduplicate concurrent refresh calls — share one promise
        if (!_refreshPromise) {
          _refreshPromise = _refreshTokens().finally(() => { _refreshPromise = null; });
        }
        await _refreshPromise;

        originalRequest.headers.Authorization = `Bearer ${useAuthStore.getState().accessToken}`;
        return api(originalRequest);
      } catch (refreshError: any) {
        // Only logout on actual auth failure (401/403), not network blips
        if (refreshError?.response?.status === 401 || refreshError?.response?.status === 403) {
          useAuthStore.getState().logout();
        }
        return Promise.reject(refreshError);
      }
    }
    return Promise.reject(error);
  }
);
