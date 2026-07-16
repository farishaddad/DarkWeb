import React, { Suspense } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { ErrorBoundary } from './components/ErrorBoundary'

const DashboardView = React.lazy(() =>
  import('./views/DashboardView').then((m) => ({ default: m.DashboardView }))
)
const AlertListView = React.lazy(() =>
  import('./views/AlertListView').then((m) => ({ default: m.AlertListView }))
)
const AlertDetailView = React.lazy(() =>
  import('./views/AlertDetailView').then((m) => ({ default: m.AlertDetailView }))
)
const SignalSourcesView = React.lazy(() =>
  import('./views/SignalSourcesView').then((m) => ({ default: m.SignalSourcesView }))
)
const RelationshipGraphView = React.lazy(() =>
  import('./views/RelationshipGraphView').then((m) => ({
    default: m.RelationshipGraphView,
  }))
)

function LoadingFallback() {
  return (
    <div className="flex items-center justify-center min-h-[400px]">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900" />
    </div>
  )
}

function App() {
  return (
    <BrowserRouter>
      <ErrorBoundary>
        <Routes>
          <Route element={<Layout />}>
            <Route
              path="/"
              element={
                <ErrorBoundary>
                  <Suspense fallback={<LoadingFallback />}>
                    <DashboardView />
                  </Suspense>
                </ErrorBoundary>
              }
            />
            <Route
              path="/alerts"
              element={
                <ErrorBoundary>
                  <Suspense fallback={<LoadingFallback />}>
                    <AlertListView />
                  </Suspense>
                </ErrorBoundary>
              }
            />
            <Route
              path="/alerts/:alertId"
              element={
                <ErrorBoundary>
                  <Suspense fallback={<LoadingFallback />}>
                    <AlertDetailView />
                  </Suspense>
                </ErrorBoundary>
              }
            />
            <Route
              path="/alerts/:alertId/sources"
              element={
                <ErrorBoundary>
                  <Suspense fallback={<LoadingFallback />}>
                    <SignalSourcesView />
                  </Suspense>
                </ErrorBoundary>
              }
            />
            <Route
              path="/graph"
              element={
                <ErrorBoundary>
                  <Suspense fallback={<LoadingFallback />}>
                    <RelationshipGraphView />
                  </Suspense>
                </ErrorBoundary>
              }
            />
          </Route>
        </Routes>
      </ErrorBoundary>
    </BrowserRouter>
  )
}

export default App
