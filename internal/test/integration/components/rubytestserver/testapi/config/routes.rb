Rails.application.routes.draw do
  resources :users

  get "/smoke", to: "users#smoke"
  get "/json_logger", to: "users#json_logger"
end
