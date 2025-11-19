<%- include('partials/header') %>

<div class="container mt-4">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <form action="/search" method="GET" class="mb-4">
                <div class="input-group">
                    <input type="text" name="q" class="form-control" placeholder="Pesquisar por espécie, variedade, origem, características..." value="<%= query %>" required>
                    <button class="btn btn-success" type="submit">
                        <i class="fas fa-search"></i> Pesquisar
                    </button>
                </div>
            </form>
        </div>
    </div>

    <% if (success) { %>
        <div class="alert alert-success text-center"><%= success %></div>
    <% } %>

    <h2 class="text-center mb-4" style="color:#27ae60;font-weight:bold">
        RESULTADOS DA PESQUISA
    </h2>

    <p class="text-center mb-4">
        <% if (total === 0) { %>
            <strong>Nenhum resultado encontrado.</strong>
        <% } else { %>
            Encontradas <strong><%= total %></strong> imagem<%= total > 1 ? 'ns' : '' %>
            <% if (query) { %> para "<em><%= query %></em>" <% } %>
        <% } %>
    </p>

    <% if (total > 0) { %>
        <div class="row">
            <% images.forEach(image => { %>
                <div class="col-md-3 mb-4">
                    <div class="card h-100 shadow-sm">
                        <a href="/uploads/<%= image.image_url %>" data-lightbox="search" data-title="<%= image.species %> <%= image.variety ? '('+image.variety+')' : '' %>">
                            <img src="/uploads/<%= image.image_url %>" class="card-img-top" alt="<%= image.species %>" style="height: 200px; object-fit: cover;">
                        </a>
                        <div class="card-body d-flex flex-column">
                            <h6 class="card-title text-center"><%= image.species %> <%= image.variety ? '('+image.variety+')' : '' %></h6>
                            <p class="text-muted small text-center">
                                <%= image.status === 'approved' ? 'Aprovada' : image.status === 'rejected' ? 'Rejeitada' : 'Pendente' %>
                            </p>
                            <div class="mt-auto text-center">
                                <div class="star-rating mb-2" data-image-id="<%= image.id %>">
                                    <% for(let i=5; i>=1; i--) { %>
                                        <i class="star <%= image.userRating >= i ? 'fas' : 'far' %> fa-star" data-value="<%= i %>"></i>
                                    <% } %>
                                    <small class="text-muted d-block">
                                        <%= image.rating_count %> voto<%= image.rating_count !== 1 ? 's' : '' %>
                                        <% if (image.rating_count > 0) { %>
                                            (<%= image.avg_rating %>/5)
                                        <% } %>
                                    </small>
                                </div>
                                <a href="/details/<%= image.id %>" class="btn btn-sm btn-outline-primary">Ver Detalhes</a>
                            </div>
                        </div>
                    </div>
                </div>
            <% }); %>
        </div>

        <!-- PAGINAÇÃO -->
        <% if (totalPages > 1) { %>
            <nav class="d-flex justify-content-center mt-4">
                <ul class="pagination">
                    <% for(let i = 1; i <= totalPages; i++) { %>
                        <li class="page-item <%= i === currentPage ? 'active' : '' %>">
                            <a class="page-link" href="/search?q=<%= encodeURIComponent(query) %>&page=<%= i %>"><%= i %></a>
                        </li>
                    <% } %>
                </ul>
            </nav>
        <% } %>
    <% } else { %>
        <div class="text-center mt-4">
            <a href="/statistics" class="btn btn-primary">Voltar às Estatísticas</a>
        </div>
    <% } %>
</div>

<%- include('partials/footer') %>