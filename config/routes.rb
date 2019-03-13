Dradis::Plugins::Calculators::CVSS::Engine.routes.draw do
  get '/calculators/cvss' => 'base#index'

  resources :projects, only: [] do
    resources :issues, only: [] do
      member do
        get   'cvss' => 'issues#edit'
        patch 'cvss' => 'issues#update'
      end
    end
  end
end
